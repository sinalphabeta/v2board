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
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;

class RiskService
{
    public const STATUS_NONE = 0;
    public const STATUS_RISK = 1;
    private const INDICATORS_CACHE_KEY = 'risk:enabled-indicators';

    public function normalizeEmail($email): string
    {
        return strtolower(trim((string)$email));
    }

    public function clientIp(Request $request): string
    {
        $remote = (string)$request->server('REMOTE_ADDR', '');
        $trusted = config('risk.trusted_proxies', '');
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
        $matches = [];
        foreach ($indicators as $indicator) {
            $value = trim((string)$indicator->value);
            if ($value === '') continue;
            $matched = false;
            if ($indicator->type === 'email') $matched = $email !== '' && $email === $this->normalizeEmail($value);
            if ($indicator->type === 'ua') $matched = $ua !== '' && strpos($ua, strtolower($value)) !== false;
            if ($indicator->type === 'ip') $matched = $this->ipMatches($ip, $value);
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
            $user->save();
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
        $ua = $request ? preg_replace('/[\x00-\x1F\x7F]+/', ' ', (string)$request->header('User-Agent', '')) : '';
        $ua = substr((string)$ua, 0, 512);
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
                RiskEvent::create([
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
        if ($count === 1) $this->notify($user, $eventType, $ip, $ua, $matches);
    }

    public function notify(?User $user, string $eventType, string $ip, string $ua, $matches = []): void
    {
        $ua = substr((string)preg_replace('/[\x00-\x1F\x7F]+/', ' ', $ua), 0, 240);
        $chatId = config('risk.alert_chat_id', '');
        if (!$chatId) return;
        $plan = $user && $user->plan_id ? Plan::find($user->plan_id) : null;
        $rules = is_array($matches)
            ? implode(',', array_map(function ($m) { return $m->type . ':' . $m->value; }, $matches))
            : (string)$matches;
        $text = "[Risk] {$eventType}\nuser_id=" . ($user ? $user->id : '-') .
            "\nemail=" . ($user ? $user->email : '-') . "\nip={$ip}\nua={$ua}" .
            "\nplan=" . ($plan ? $plan->name : '-') . "\ngroup=" . ($user ? $user->group_id : '-') . "\nrules={$rules}";
        $token = (string)config('risk.bot_token', '');
        if (!$token) return;
        try { SendRiskTelegramJob::dispatch((int)$chatId, $text); } catch (\Throwable $e) { /* queue unavailable */ }
    }

    public function addIndicator(string $type, string $value, ?string $note = null, ?int $actorId = null): RiskIndicator
    {
        $value = $type === 'email' ? $this->normalizeEmail($value) : trim($value);
        $indicator = RiskIndicator::updateOrCreate(['type' => $type, 'value' => $value], ['note' => $note, 'enabled' => 1]);
        Cache::forget(self::INDICATORS_CACHE_KEY);
        $this->audit('add', $indicator, $actorId);
        if ($type === 'email') {
            User::whereRaw('LOWER(TRIM(email)) = ?', [$value])->get()->each(function ($user) use ($indicator) {
                $this->reconcileEmailRisk($user);
            });
        }
        return $indicator;
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

    private function reconcileEmailRisk(User $user): void
    {
        $indicator = RiskIndicator::where('type', 'email')
            ->where('enabled', 1)
            ->whereRaw('LOWER(TRIM(value)) = ?', [$this->normalizeEmail($user->email)])
            ->orderBy('id', 'asc')
            ->first();
        if ($indicator) {
            $user->risk_status = self::STATUS_RISK;
            $user->risk_indicator_id = $indicator->id;
            if (!$user->risk_marked_at) $user->risk_marked_at = time();
            $user->save();
        } elseif ((int)$user->risk_status === self::STATUS_RISK) {
            $user->risk_status = self::STATUS_NONE;
            $user->risk_indicator_id = null;
            $user->risk_marked_at = null;
            $user->save();
        }
    }

    public function removeIndicator(RiskIndicator $indicator, ?int $actorId = null): bool
    {
        $indicator->enabled = 0;
        $ok = $indicator->save();
        if ($ok) {
            $this->audit('delete', $indicator, $actorId);
            $this->refreshEmailIndicator($indicator);
        }
        return $ok;
    }

    public function audit(string $action, RiskIndicator $indicator, ?int $actorId): void
    {
        try { RiskAudit::create(['actor_id' => $actorId, 'action' => $action, 'indicator_id' => $indicator->id, 'type' => $indicator->type, 'value' => $indicator->value, 'created_at' => time()]); } catch (\Throwable $e) { }
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
        $honeypot = (int)config('risk.honeypot_group_id', 0);
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

    private function ipMatchesAny(string $ip, array $rules): bool
    {
        foreach ($rules as $rule) if ($this->ipMatches($ip, trim((string)$rule))) return true;
        return false;
    }
}
