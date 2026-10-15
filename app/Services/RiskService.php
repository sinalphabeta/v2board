<?php

namespace App\Services;

use App\Jobs\SendRiskTelegramJob;
use App\Models\Plan;
use App\Models\RiskAudit;
use App\Models\RiskEvent;
use App\Models\RiskIndicator;
use App\Models\ServerAnytls;
use App\Models\ServerHysteria;
use App\Models\ServerShadowsocks;
use App\Models\ServerTrojan;
use App\Models\ServerTuic;
use App\Models\ServerV2node;
use App\Models\ServerVless;
use App\Models\ServerVmess;
use App\Models\User;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;

class RiskService
{
    public const STATUS_NONE = 0;
    public const STATUS_RISK = 1;
    private const INDICATORS_CACHE_KEY = 'risk:enabled-indicators';
    private $ipInfoService;
    private $actor = ['type' => 'system', 'id' => null, 'ip' => null];

    public function __construct(?IpInfoService $ipInfoService = null)
    {
        $this->ipInfoService = $ipInfoService ?: app(IpInfoService::class);
    }

    /**
     * Who makes the following changes, for the audit log: 'admin' (the admin's user id and IP), 'bot' (the admin's
     * user id), or 'system' (the default, e.g. marking a user at registration). Older rows may also say 'api'.
     */
    public function actingAs(string $type, ?int $id = null, ?string $ip = null): self
    {
        $this->actor = ['type' => $type, 'id' => $id, 'ip' => $ip];
        return $this;
    }

    public function normalizeEmail($email): string
    {
        return strtolower(trim((string)$email));
    }

    public function normalizeAsn($value): ?string
    {
        $value = trim((string)$value);
        if (!preg_match('/^(?:AS)?([0-9]+)$/i', $value, $matches)) return null;
        $number = ltrim($matches[1], '0');
        if ($number === '') $number = '0';
        if ($number === '0' || strlen($number) > 10) return null;
        if (strlen($number) === 10 && strcmp($number, '4294967295') > 0) return null;
        return 'AS' . $number;
    }

    /**
     * The value stored for an indicator of this type, or null if the value is not valid for it.
     */
    public function normalizeIndicatorValue(string $type, $value): ?string
    {
        $value = trim((string)$value);
        if ($type === 'email') $value = $this->normalizeEmail($value);
        if ($type === 'asn') $value = (string)$this->normalizeAsn($value);
        if ($value === '' || mb_strlen($value, 'UTF-8') > 255) return null;
        if ($type === 'email') return filter_var($value, FILTER_VALIDATE_EMAIL) ? $value : null;
        if ($type === 'ip') {
            [$address, $bits] = array_pad(explode('/', $value, 2), 2, null);
            if (!filter_var($address, FILTER_VALIDATE_IP)) return null;
            $max = filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) ? 128 : 32;
            return $bits === null || (ctype_digit($bits) && (int)$bits <= $max) ? $value : null;
        }
        return in_array($type, ['ua', 'asn'], true) ? $value : null;
    }

    /**
     * Users matching a uid, an email, or an IP recorded in their risk events (the newest first).
     */
    public function findUsers(string $query, int $limit = 10)
    {
        $query = trim($query);
        if ($query === '') return collect();
        if (ctype_digit($query)) return User::where('id', (int)$query)->get();
        if (filter_var($query, FILTER_VALIDATE_IP)) {
            $ids = RiskEvent::where('ip', $query)->whereNotNull('user_id')->orderByDesc('last_seen_at')
                ->limit(200)->pluck('user_id')->unique()->take($limit)->values();
            $users = User::whereIn('id', $ids)->get()->keyBy('id');
            return $ids->map(function ($id) use ($users) { return $users->get($id); })->filter()->values();
        }
        return User::where('email', $this->normalizeEmail($query))->get();
    }

    public function clientIp(Request $request): string
    {
        $remote = (string)$request->server('REMOTE_ADDR', '');
        $trusted = RiskSettings::get('trusted_proxies');
        if (!is_array($trusted)) $trusted = array_filter(array_map('trim', explode(',', (string)$trusted)));
        if ($remote && $this->ipMatchesAny($remote, $trusted)) {
            foreach (['HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR'] as $header) {
                $value = $request->server($header);
                if ($value) {
                    $candidate = trim(explode(',', $value)[0]);
                    if (filter_var($candidate, FILTER_VALIDATE_IP)) return $candidate;
                }
            }
        }
        $candidate = $remote ?: (string)$request->ip();
        return filter_var($candidate, FILTER_VALIDATE_IP) ? $candidate : '0.0.0.0';
    }

    public function indicatorsFor(string $type, $value = null)
    {
        $query = RiskIndicator::where('type', $type)->where('enabled', 1);
        if ($value !== null) $query->where('value', $value);
        return $query->get();
    }

    public function matches(string $email, string $ip, string $ua): array
    {
        try {
            $indicators = Cache::remember(self::INDICATORS_CACHE_KEY, 60, function () {
                return RiskIndicator::where('enabled', 1)->get();
            });
        } catch (\Throwable $e) {
            return [];
        }
        $email = $this->normalizeEmail($email);
        $ua = strtolower($ua);
        $asn = null;
        foreach ($indicators as $indicator) {
            if ($indicator->type === 'asn') {
                $asn = $this->lookupAsn($ip);
                break;
            }
        }
        $matches = [];
        foreach ($indicators as $indicator) {
            $value = trim((string)$indicator->value);
            if ($value === '') continue;
            $matched = false;
            if ($indicator->type === 'email') $matched = $email !== '' && $email === $this->normalizeEmail($value);
            if ($indicator->type === 'ua') $matched = $ua !== '' && strpos($ua, strtolower($value)) !== false;
            if ($indicator->type === 'ip') $matched = $this->ipMatches($ip, $value);
            if ($indicator->type === 'asn') $matched = $asn !== null && $asn === $this->normalizeAsn($value);
            if ($matched) $matches[] = $indicator;
        }
        return $matches;
    }

    public function markUser(User $user, array $matches, Request $request = null, bool $record = true): User
    {
        $emailMatch = null;
        foreach ($matches as $match) if ($match->type === 'email') { $emailMatch = $match; break; }
        if ($emailMatch && !$user->risk_status) {
            $user->risk_status = self::STATUS_RISK;
            $user->risk_indicator_id = $emailMatch->id;
            $user->risk_marked_at = time();
            $this->saveUserRisk($user, $emailMatch);
        }
        if ($record && $matches) {
            $this->recordEvent($user, 'identity', $request, $matches);
        }
        return $user;
    }

    public function observe(User $user, string $eventType, Request $request, bool $allowMark = false): array
    {
        $ip = $this->clientIp($request);
        $ua = (string)$request->header('User-Agent', '');
        $matches = $this->matches((string)$user->email, $ip, $ua);
        if ($allowMark && $matches) $this->markUser($user, $matches, $request, false);
        if ($matches || (int)$user->risk_status) {
            $this->recordEvent($user, $eventType, $request, $matches);
        }
        return $matches;
    }

    public function recordEvent(?User $user, string $eventType, ?Request $request, array $matches = []): void
    {
        $ip = $request ? $this->clientIp($request) : '0.0.0.0';
        $ua = $request ? $this->cleanUserAgent($request->header('User-Agent', ''), 512) : '';
        $ruleIds = array_map(function ($m) { return (string)$m->id; }, $matches);
        sort($ruleIds);
        $target = $user ? 'user:' . $user->id : 'target:global';
        $fingerprint = hash('sha256', implode('|', [$target, $eventType, $ip, strtolower($ua), implode(',', $ruleIds)]));
        $key = 'risk:event:' . $fingerprint;
        $now = time();
        $cacheAvailable = true;
        try {
            $count = (int)Cache::get($key, 0);
            if ($count === 0) {
                Cache::put($key, 1, 86400);
                $count = 1;
            } else {
                $count = (int)Cache::increment($key);
            }
        } catch (\Throwable $e) {
            // Observability must never make login/subscription fail.
            $cacheAvailable = false;
            $count = 1;
        }
        $shouldSync = !$cacheAvailable || $count === 1;
        if (!$shouldSync) {
            try {
                $shouldSync = Cache::add($key . ':db-sync', 1, 300);
            } catch (\Throwable $e) {
                $shouldSync = true;
            }
        }
        if (!$shouldSync) return;
        try {
            $event = RiskEvent::where('fingerprint', $fingerprint)->first();
            if ($event) {
                $event->last_seen_at = $now;
                try { $lastSyncedCount = (int)Cache::get($key . ':db-count', 0); } catch (\Throwable $e) { $lastSyncedCount = 0; }
                $event->occurrences = max(1, (int)$event->occurrences + max(1, $count - $lastSyncedCount));
                $event->save();
            } else {
                $event = RiskEvent::create([
                    'fingerprint' => $fingerprint, 'user_id' => $user ? $user->id : null,
                    'event_type' => $eventType, 'ip' => $ip, 'user_agent' => $ua,
                    'indicator_ids' => json_encode($ruleIds), 'first_seen_at' => $now,
                    'last_seen_at' => $now, 'occurrences' => 1
                ]);
            }
            try { Cache::put($key . ':db-count', $count, 86400); } catch (\Throwable $e) { }
        } catch (\Throwable $e) {
            return;
        }
        if ($count === 1) $this->notify($user, $eventType, $ip, $ua, $matches, (int)$event->id);
    }

    /**
     * Send a risk alert to the alert chat; with a user and an event it carries the risk bot's action buttons.
     */
    public function notify(?User $user, string $eventType, string $ip, string $ua, $matches = [], ?int $eventId = null): void
    {
        $ua = $this->cleanUserAgent($ua, 240);
        $chatId = RiskSettings::get('alert_chat_id');
        if (!$chatId) return;
        $plan = $user && $user->plan_id ? Plan::find($user->plan_id) : null;
        $rules = is_array($matches)
            ? implode(',', array_map(function ($m) { return $m->type . ':' . $m->value; }, $matches))
            : (string)$matches;
        $escape = function ($value): string {
            return preg_replace_callback('/[_*\[\]()~`>#+\-=|{}.!\\\\]/', function ($match) {
                return '\\' . $match[0];
            }, (string)$value);
        };
        $code = function ($value): string {
            return '`' . str_replace(['\\', '`'], ['\\\\', '\\`'], (string)$value) . '`';
        };
        $text = "*\\[RISK\\]* _" . $escape($eventType) . "_\nuid: `" . ($user ? (int)$user->id : '-') . "`" .
            "\nemail: " . $code($user ? $user->email : '-') . "\nip: " . $code($ip) . "\nua: " . $code($ua) .
            "\nplan: " . $code($plan ? $plan->name : '-') . "\ngroup: " . $code($user ? $user->group_id : '-') .
            "\nrules: " . $code($rules);
        $token = (string)RiskSettings::get('bot_token');
        if (!$token) return;
        try {
            SendRiskTelegramJob::dispatch((int)$chatId, $text, $ip, $user ? (int)$user->id : null, $eventId);
        } catch (\Throwable $e) { /* queue unavailable */ }
    }

    public function addIndicator(string $type, string $value, ?string $note = null): RiskIndicator
    {
        $normalized = $this->normalizeIndicatorValue($type, $value);
        if ($normalized === null) throw new \InvalidArgumentException("Invalid {$type} indicator: {$value}");
        $value = $normalized;
        $indicator = RiskIndicator::firstOrNew(['type' => $type, 'value' => $value]);
        // Adding an indicator that is already enabled only changes its note
        $action = $indicator->exists && $indicator->enabled ? 'edit' : 'add';
        $indicator->fill(['note' => $note, 'enabled' => 1]);
        $this->saveIndicator($indicator, $action);
        if ($type === 'email') {
            User::whereRaw('LOWER(TRIM(email)) = ?', [$value])->get()->each(function ($user) use ($indicator) {
                $this->reconcileEmailRisk($user);
            });
        }
        return $indicator;
    }

    public function updateIndicator(RiskIndicator $indicator, array $attributes): bool
    {
        $indicator->fill($attributes);
        $ok = $this->saveIndicator($indicator, 'edit');
        if ($ok) $this->refreshEmailIndicator($indicator);
        return $ok;
    }

    public function refreshEmailIndicator(RiskIndicator $indicator): void
    {
        Cache::forget(self::INDICATORS_CACHE_KEY);
        if ($indicator->type !== 'email') return;
        User::where('risk_indicator_id', $indicator->id)->get()->each(function ($user) {
            $this->reconcileEmailRisk($user);
        });
        if ((int)$indicator->enabled === 1) {
            User::whereRaw('LOWER(TRIM(email)) = ?', [$this->normalizeEmail($indicator->value)])
                ->get()->each(function ($user) { $this->reconcileEmailRisk($user); });
        }
    }

    /**
     * Isolate a user by adding their email to the email indicators; an existing indicator keeps its note.
     */
    public function isolateUser(User $user, ?string $note = null): RiskIndicator
    {
        $existing = RiskIndicator::where('type', 'email')->where('value', $this->normalizeEmail($user->email))->first();
        return $this->addIndicator('email', (string)$user->email, $note ?? ($existing ? $existing->note : null));
    }

    /**
     * Release a user by disabling the email indicators that match their email. Returns whether they are released.
     */
    public function releaseUser(User $user): bool
    {
        foreach ($this->enabledEmailIndicators($user->email) as $indicator) $this->removeIndicator($indicator);
        $user->refresh();
        // Marked by an indicator that no longer matches the email, e.g. after the email was changed
        if ((int)$user->risk_status === self::STATUS_RISK) $this->reconcileEmailRisk($user);
        return (int)$user->risk_status !== self::STATUS_RISK;
    }

    private function enabledEmailIndicators($email)
    {
        return RiskIndicator::where('type', 'email')
            ->where('enabled', 1)
            ->whereRaw('LOWER(TRIM(value)) = ?', [$this->normalizeEmail($email)])
            ->orderBy('id', 'asc')
            ->get();
    }

    private function reconcileEmailRisk(User $user): void
    {
        $indicator = $this->enabledEmailIndicators($user->email)->first();
        if ($indicator) {
            $user->risk_status = self::STATUS_RISK;
            $user->risk_indicator_id = $indicator->id;
            if (!$user->risk_marked_at) $user->risk_marked_at = time();
            $this->saveUserRisk($user, $indicator);
        } elseif ((int)$user->risk_status === self::STATUS_RISK) {
            $previous = $user->risk_indicator_id ? RiskIndicator::find($user->risk_indicator_id) : null;
            $user->risk_status = self::STATUS_NONE;
            $user->risk_indicator_id = null;
            $user->risk_marked_at = null;
            $this->saveUserRisk($user, $previous);
        }
    }

    public function removeIndicator(RiskIndicator $indicator): bool
    {
        $indicator->enabled = 0;
        $ok = $this->saveIndicator($indicator, 'delete');
        if ($ok) $this->refreshEmailIndicator($indicator);
        return $ok;
    }

    private function saveIndicator(RiskIndicator $indicator, string $action): bool
    {
        $changes = $this->changes($indicator, ['value', 'note', 'enabled']);
        if (!$changes) return true;
        if (!$indicator->save()) return false;
        Cache::forget(self::INDICATORS_CACHE_KEY);
        $this->audit($action, $indicator, $changes);
        return true;
    }

    private function saveUserRisk(User $user, ?RiskIndicator $indicator): void
    {
        $changes = $this->changes($user, ['risk_status', 'risk_indicator_id']);
        $user->save();
        if ($changes) $this->audit($user->risk_status ? 'mark' : 'unmark', $indicator, $changes, $user);
    }

    /**
     * The fields of an unsaved model that will change, as [field => [old, new]].
     */
    private function changes(Model $model, array $fields): array
    {
        $changes = [];
        foreach ($fields as $field) {
            if (!$model->isDirty($field)) continue;
            $old = $model->getOriginal($field);
            $new = $model->getAttribute($field);
            if ($old !== $new) $changes[$field] = [$old, $new];
        }
        return $changes;
    }

    private function audit(string $action, ?RiskIndicator $indicator, array $changes, ?User $user = null): void
    {
        try {
            RiskAudit::create([
                'actor_type' => $this->actor['type'], 'actor_id' => $this->actor['id'], 'actor_ip' => $this->actor['ip'],
                'action' => $action, 'indicator_id' => $indicator ? $indicator->id : null, 'user_id' => $user ? $user->id : null,
                // Users are only marked through email indicators
                'type' => $indicator ? $indicator->type : 'email',
                'value' => $indicator ? $indicator->value : $this->normalizeEmail($user ? $user->email : ''),
                'changes' => $changes, 'created_at' => time()
            ]);
        } catch (\Throwable $e) { }
    }

    /**
     * Audit a changed risk setting. The bot token and the alert chat ID are only recorded as set (with their last
     * 4 characters) or empty, never in full.
     */
    public function auditSetting(string $name, $old, $new): void
    {
        $mask = function ($value) use ($name) {
            if (!in_array($name, ['bot_token', 'alert_chat_id'], true) || $value === '' || $value === null) return $value;
            return '已设置（…' . mb_substr((string)$value, -4, null, 'UTF-8') . '）';
        };
        try {
            RiskAudit::create([
                'actor_type' => $this->actor['type'], 'actor_id' => $this->actor['id'], 'actor_ip' => $this->actor['ip'],
                'action' => 'setting', 'type' => 'setting', 'value' => $name,
                'changes' => ['value' => [$mask($old), $mask($new)]], 'created_at' => time()
            ]);
        } catch (\Throwable $e) { }
    }

    public function cleanup(int $days = 90): int
    {
        try { return RiskEvent::where('last_seen_at', '<', time() - $days * 86400)->delete(); } catch (\Throwable $e) { return 0; }
    }

    /**
     * Return active nodes that combine the honeypot group with another group.
     */
    public function mixedHoneypotNodes(): array
    {
        $honeypot = (int)RiskSettings::get('honeypot_group_id');
        if ($honeypot <= 0) return [];

        $models = [
            'shadowsocks' => ServerShadowsocks::class,
            'vmess' => ServerVmess::class,
            'trojan' => ServerTrojan::class,
            'tuic' => ServerTuic::class,
            'hysteria' => ServerHysteria::class,
            'vless' => ServerVless::class,
            'anytls' => ServerAnytls::class,
            'v2node' => ServerV2node::class,
        ];
        $mixed = [];
        foreach ($models as $type => $model) {
            try {
                $nodes = $model::query()->get(['id', 'group_id', 'show']);
            } catch (\Throwable $e) {
                continue;
            }
            foreach ($nodes as $node) {
                if (isset($node->show) && !(int)$node->show) continue;
                $groups = is_array($node->group_id) ? array_map('intval', $node->group_id) : [];
                if (in_array($honeypot, $groups, true) && count(array_diff($groups, [$honeypot])) > 0) {
                    $mixed[] = $type . '#' . $node->id;
                }
            }
        }
        return $mixed;
    }

    public function ipMatches(string $ip, string $rule): bool
    {
        if (!filter_var($ip, FILTER_VALIDATE_IP)) return false;
        if (strpos($rule, '/') === false) {
            return filter_var($rule, FILTER_VALIDATE_IP) && inet_pton($rule) === inet_pton($ip);
        }
        [$network, $bits] = explode('/', $rule, 2);
        if (!filter_var($network, FILTER_VALIDATE_IP) || !is_numeric($bits)) return false;
        $ipBin = inet_pton($ip); $networkBin = inet_pton($network);
        if ($ipBin === false || $networkBin === false || strlen($ipBin) !== strlen($networkBin)) return false;
        $bits = (int)$bits; $max = strlen($ipBin) * 8;
        if ($bits < 0 || $bits > $max) return false;
        $bytes = intdiv($bits, 8); $rem = $bits % 8;
        if ($bytes && substr($ipBin, 0, $bytes) !== substr($networkBin, 0, $bytes)) return false;
        if ($rem) { $mask = chr((0xff << (8 - $rem)) & 0xff); if ((ord($ipBin[$bytes]) & ord($mask)) !== (ord($networkBin[$bytes]) & ord($mask))) return false; }
        return true;
    }

    /**
     * Replace invalid UTF-8 and control characters, then cut by characters: a cut by bytes can split a multibyte
     * character, which MySQL (strict mode) and Telegram reject.
     */
    private function cleanUserAgent($ua, int $length): string
    {
        $ua = preg_replace('/[\x00-\x1F\x7F]+/', ' ', mb_scrub((string)$ua, 'UTF-8'));
        return mb_substr((string)$ua, 0, $length, 'UTF-8');
    }

    private function ipMatchesAny(string $ip, array $rules): bool
    {
        foreach ($rules as $rule) if ($this->ipMatches($ip, trim((string)$rule))) return true;
        return false;
    }

    private function lookupAsn(string $ip): ?string
    {
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) return null;

        $lookup = function () use ($ip): array {
            $result = $this->ipInfoService->lookupAsn($ip);
            return ['asn_number' => $this->normalizeAsn($result['asn_number'] ?? null)];
        };
        $ttl = max(0, (int)RiskSettings::get('asn_cache_ttl'));
        if ($ttl === 0) return $lookup()['asn_number'];

        try {
            $result = Cache::remember('risk:asn:' . hash('sha256', $ip), $ttl, $lookup);
        } catch (\Throwable $e) {
            $result = $lookup();
        }
        return is_array($result) ? ($result['asn_number'] ?? null) : null;
    }
}
