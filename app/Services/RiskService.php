<?php

namespace App\Services;

use App\Exceptions\RiskIpAllowlistedException;
use App\Jobs\SendRiskTelegramJob;
use App\Models\Plan;
use App\Models\RiskAccess;
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
use App\Utils\Helper;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;

class RiskService
{
    public const STATUS_NONE = 0;
    public const STATUS_RISK = 1;
    /**
     * Risk events that are not a matched request but something a check found (recordFinding()), with what it found in
     * the event's detail.
     */
    public const FINDING_TYPES = [
        'sub_limit' => '订阅超限', 'ip_users' => '同 IP 多用户', 'register_link' => '注册关联', 'sub_burst' => '订阅过频',
    ];
    /**
     * Indicator types. allow_ip is an allowlist: requests from its IPs skip the IP and ASN rules. The others are
     * risk rules (RULE_TYPES): a match is recorded and alerted, and an email match also isolates the user.
     */
    public const TYPES = ['email' => '邮箱', 'ip' => 'IP', 'ua' => 'UA', 'asn' => 'ASN', 'allow_ip' => 'IP 白名单'];
    public const LIST_NAMES = ['email' => '邮箱名单', 'ip' => 'IP 名单', 'ua' => 'UA 名单', 'asn' => 'ASN 名单', 'allow_ip' => 'IP 白名单'];
    public const RULE_TYPES = ['email', 'ip', 'ua', 'asn'];
    // The shortest allowlist prefix by address length: at most a /16 (IPv4) or /48 (IPv6) is let through at once
    private const ALLOW_MIN_PREFIX = [32 => 16, 128 => 48];
    public const ALLOW_IP_FORMAT = 'IP 白名单只接受 IP，或不大于 /16（IPv6 /48）的网段，也不能是 0.0.0.0 或 ::';
    private const INDICATORS_CACHE_KEY = 'risk:enabled-indicators';
    private $ipInfoService;
    private $access;
    private $links;
    private $alerts;
    private $actor = ['type' => 'system', 'id' => null, 'ip' => null];

    public function __construct(?IpInfoService $ipInfoService = null)
    {
        $this->ipInfoService = $ipInfoService ?: app(IpInfoService::class);
    }

    public function access(): RiskAccessService
    {
        if (!$this->access) $this->access = new RiskAccessService($this);
        return $this->access;
    }

    public function links(): RiskLinkService
    {
        if (!$this->links) $this->links = new RiskLinkService($this);
        return $this->links;
    }

    public function alerts(): RiskAlertService
    {
        if (!$this->alerts) $this->alerts = new RiskAlertService();
        return $this->alerts;
    }

    /**
     * Who makes the following changes, for the audit log: 'admin' (the admin's user id and IP), 'tg' (the Telegram ID
     * of whoever used the risk bot), or 'system' (the default, e.g. marking a user at registration). Older rows may also
     * say 'bot' (the bound admin's user id) or 'api'.
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
        if ($type === 'ip' || $type === 'allow_ip') return $this->normalizeIpRange($value, $type === 'allow_ip');
        return in_array($type, ['ua', 'asn'], true) ? $value : null;
    }

    /**
     * An IP or CIDR in its standard form, e.g. 2001:DB8:0::1 → 2001:db8::1, 1.2.3.4/32 → 1.2.3.4 and
     * 1.2.3.4/24 → 1.2.3.0/24, or null if it is not one. For the allowlist also null for 0.0.0.0, :: and the ranges
     * containing them (0.0.0.0 is recorded when the client IP is unknown), and for ranges larger than ALLOW_MIN_PREFIX.
     */
    private function normalizeIpRange(string $value, bool $allowlist): ?string
    {
        $range = $this->parseIpRange($value);
        if ($range === null) return null;
        [$binary, $bits, $max] = $range;
        // Clear the host bits
        $bytes = intdiv($bits, 8);
        $network = substr($binary, 0, $bytes);
        if ($bits % 8) $network .= chr(ord($binary[$bytes]) & (0xff << (8 - $bits % 8)) & 0xff);
        $network = str_pad($network, strlen($binary), "\0");
        if ($allowlist && ($bits < self::ALLOW_MIN_PREFIX[$max] || trim($network, "\0") === '')) return null;
        $address = inet_ntop($network);
        return $bits === $max ? $address : "{$address}/{$bits}";
    }

    /**
     * [address in binary, prefix length, address length in bits] of an IP (as a /32 or /128) or a CIDR, or null.
     */
    private function parseIpRange(string $value): ?array
    {
        [$address, $bits] = array_pad(explode('/', trim($value), 2), 2, null);
        if (!filter_var($address, FILTER_VALIDATE_IP)) return null;
        $binary = inet_pton($address);
        $max = strlen($binary) * 8;
        if ($bits === null) return [$binary, $max, $max];
        if (!ctype_digit($bits) || (int)$bits > $max) return null;
        return [$binary, (int)$bits, $max];
    }

    /**
     * Whether the IP or CIDR $inner lies entirely within $outer: the same IP version, a prefix at least as long, and
     * its address within $outer (so a CIDR with host bits set, like 1.2.3.4/24, counts as its network).
     */
    public function ipRangeWithin(string $inner, string $outer): bool
    {
        $innerRange = $this->parseIpRange($inner);
        $outerRange = $this->parseIpRange($outer);
        if ($innerRange === null || $outerRange === null || $innerRange[2] !== $outerRange[2]) return false;
        return $innerRange[1] >= $outerRange[1] && $this->ipMatches(inet_ntop($innerRange[0]), trim($outer));
    }

    /**
     * The enabled IP allowlist entry that covers this IP or CIDR, read from the database (not the indicator cache).
     */
    public function allowEntryFor(string $ipOrCidr): ?RiskIndicator
    {
        return RiskIndicator::where('type', 'allow_ip')->where('enabled', 1)->orderBy('id')->get()
            ->first(function (RiskIndicator $entry) use ($ipOrCidr) {
                return $this->ipRangeWithin($ipOrCidr, $entry->value);
            });
    }

    /**
     * What allowlisting an event's IP adds: the IP, or for IPv6 its /64 since clients rotate their IPv6 addresses.
     * Null for a private or reserved IP.
     */
    public function allowRangeFor(string $ip): ?string
    {
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) return null;
        return $this->normalizeIndicatorValue('allow_ip', filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) ? "{$ip}/64" : $ip);
    }

    /**
     * How many users each of these IPs had in the last 30 days (an IPv6 address counts its /64), as [ip => count];
     * IPs without any are left out.
     */
    public function recentUserCounts(array $ips): array
    {
        $counts = [];
        foreach ($this->ipUsage($ips, 30) as $ip => $users) if ($users) $counts[$ip] = count($users);
        return $counts;
    }

    /**
     * Who used these IPs in the last $days days, by IP as given: [ip => [user_id => [type => times…,
     * 'last_seen_at' => time]]] with the types subscription, login, register and order. From the access log (an IPv6
     * address by its /64; a /64 may also be given as such) and the risk events, which go back to before the access log
     * began; a request in both is counted once.
     */
    public function ipUsage(array $ips, int $days): array
    {
        $ips = array_values(array_unique(array_filter(array_map('strval', $ips), 'strlen')));
        if (!$ips) return [];
        $access = $this->access();
        $usage = $access->usage($ips, $days);
        $nets = [];
        foreach ($ips as $ip) $nets[$ip] = strpos($ip, '/') !== false ? $ip : $access->ipNet($ip);
        $exact = array_values(array_filter($ips, function ($ip) { return strpos($ip, ':') === false && strpos($ip, '/') === false; }));
        $ipv6 = count($exact) < count($ips);
        if (!$exact && !$ipv6) return $usage;
        $events = RiskEvent::whereNotNull('user_id')->where('last_seen_at', '>=', time() - $days * 86400)
            ->whereIn('event_type', ['subscription', 'login', 'register'])
            ->where(function ($query) use ($exact, $ipv6) {
                if ($exact) $query->whereIn('ip', $exact);
                // An IPv6 event matches by its /64, which its text does not show: check them all
                if ($ipv6) $query->orWhere('ip', 'like', '%:%');
            })->get(['ip', 'user_id', 'event_type', 'occurrences', 'last_seen_at']);
        foreach ($events as $event) {
            $net = $access->ipNet((string)$event->ip);
            foreach ($nets as $ip => $want) {
                if ($want !== $net) continue;
                $entry = $usage[$ip][(int)$event->user_id] ?? [];
                // An isolated user's requests are both logged and risk events: take the larger count, not the sum
                $entry[$event->event_type] = max((int)($entry[$event->event_type] ?? 0), (int)$event->occurrences);
                $entry['last_seen_at'] = max((int)($entry['last_seen_at'] ?? 0), (int)$event->last_seen_at);
                $usage[$ip][(int)$event->user_id] = $entry;
            }
        }
        return $usage;
    }

    /**
     * Users matching a uid, an email, or an IP they used within the access log's days (see ipUsage(); the latest
     * first).
     */
    public function findUsers(string $query, int $limit = 10)
    {
        $query = trim($query);
        if ($query === '') return collect();
        if (ctype_digit($query)) return User::where('id', (int)$query)->get();
        if (filter_var($query, FILTER_VALIDATE_IP)) {
            $usage = $this->ipUsage([$query], $this->searchDays())[$query] ?? [];
            uasort($usage, function ($a, $b) { return ($b['last_seen_at'] ?? 0) <=> ($a['last_seen_at'] ?? 0); });
            $ids = array_slice(array_keys($usage), 0, $limit);
            $users = User::whereIn('id', $ids)->get()->keyBy('id');
            return collect($ids)->map(function ($id) use ($users) { return $users->get($id); })->filter()->values();
        }
        return User::where('email', $this->normalizeEmail($query))->get();
    }

    /**
     * How far back /search looks for an IP: the access log's days (the risk events are kept 90 days).
     */
    public function searchDays(): int
    {
        return max(1, (int)RiskSettings::get('access_log_days'));
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

    /**
     * Who a per-visitor limit counts: the real IP, an IPv6 address by its /64 (one address each would let anyone with
     * a /64 change address to get round it). $request->ip() is nginx's 127.0.0.1 under webman, the same for everyone.
     */
    public function clientNet(Request $request): string
    {
        return $this->access()->ipNet($this->clientIp($request));
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
        // An allowlisted IP skips the IP and ASN rules, so its ASN is not looked up either
        $allowed = false;
        foreach ($indicators as $indicator) {
            if ($indicator->type === 'allow_ip' && $this->ipMatches($ip, trim((string)$indicator->value))) {
                $allowed = true;
                break;
            }
        }
        $asn = null;
        foreach ($indicators as $indicator) {
            if ($indicator->type === 'asn' && !$allowed) {
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
            if ($indicator->type === 'ip') $matched = !$allowed && $this->ipMatches($ip, $value);
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

    /**
     * Check a request against the indicators (an email match isolates the user if $allowMark) and record it: as a
     * risk event when it matches or the user is isolated, and in the access log as $result, unless that is null.
     * A registration is also checked for links to other accounts (RiskLinkService).
     */
    public function observe(User $user, string $eventType, Request $request, bool $allowMark = false, ?string $result = 'ok', int $count = 0): array
    {
        $ip = $this->clientIp($request);
        $ua = (string)$request->header('User-Agent', '');
        $matches = $this->matches((string)$user->email, $ip, $ua);
        if ($allowMark && $matches) $this->markUser($user, $matches, $request, false);
        if ($matches || (int)$user->risk_status) {
            $this->recordEvent($user, $eventType, $request, $matches);
        }
        if ($result !== null) {
            if ($eventType === 'register' && (int)$user->risk_status === self::STATUS_RISK) $result = 'isolated';
            $this->access()->record($user, $eventType, $request, $result, $count);
            if ($eventType === 'register') $this->links()->checkRegistration($user, $request);
        }
        return $matches;
    }

    /**
     * Record a request that is not checked against the indicators: a wrong password, an order.
     */
    public function recordAccess(User $user, string $type, Request $request, string $result = 'ok'): void
    {
        $this->access()->record($user, $type, $request, $result);
    }

    /**
     * The client middleware's check once it has the user of a subscription token: observe and log the request, and
     * answer a subscription over the daily limit with RiskAccessService::limitResponse() instead of the nodes (null
     * otherwise). client/app/getVersion (no nodes) and HEAD requests are observed but neither counted nor logged.
     */
    public function guardClient(User $user, Request $request)
    {
        $route = $request->route();
        if (($route && $route->getActionMethod() === 'getVersion') || $request->isMethod('HEAD')) {
            $this->observe($user, 'subscription', $request, false, null);
            return null;
        }
        $access = $this->access();
        $count = $access->countSubscription($user);
        $limited = $access->overLimit($user, $count);
        if ((int)$user->risk_status === self::STATUS_RISK) $result = 'isolated';
        elseif ($limited) $result = 'limited';
        elseif (!(new UserService())->isAvailable($user)) $result = 'unavailable';
        else $result = 'ok';
        $this->observe($user, 'subscription', $request, false, $result, $count);
        // Many in a few minutes looks like a script: alerted once a day (not for isolated users, nor those let through)
        if ($access->burstLimit() > 0 && $result !== 'isolated' && !$access->exempt($user)) {
            $burst = $access->countBurst($user);
            if ($burst >= $access->burstLimit()) $this->burstAlert($user, $request, $burst);
        }
        if (!$limited) return null;
        $this->limitAlert($user, $request, $count);
        return $access->limitResponse();
    }

    /**
     * Let the user subscribe without the daily limit until midnight (今天放行).
     */
    public function exemptToday(User $user): void
    {
        $this->access()->exemptToday($user);
        $this->audit('exempt', null, [], $user);
    }

    /**
     * Give the user a new subscription token and UUID, as the admin panel's 重置UUID及订阅URL does: the old
     * subscription link stops working at once, and the nodes refuse the old UUID within about a minute.
     */
    public function resetSubscription(User $user): bool
    {
        $user->token = Helper::guid();
        $user->uuid = Helper::guid(true);
        if (!$user->save()) return false;
        $this->audit('reset', null, [], $user);
        return true;
    }

    /**
     * Record what a check found about a user as a risk event of a FINDING_TYPES type, with $detail as the evidence, and
     * alert it (see notify()). $key identifies the finding: recording it again updates the same event (and alerts again
     * unless $alert is false). 注册关联 alerts are merged by the registration IP (an IPv6 /64).
     */
    public function recordFinding(User $user, string $type, string $ip, string $ua, string $detail, string $key, bool $alert = true): ?RiskEvent
    {
        $ua = $this->cleanUserAgent($ua, 512);
        $detail = mb_substr($detail, 0, 255, 'UTF-8');
        $now = time();
        try {
            $fingerprint = hash('sha256', 'finding|' . $key);
            $event = RiskEvent::where('fingerprint', $fingerprint)->first();
            if ($event) {
                $event->fill(['user_id' => $user->id, 'ip' => $ip, 'user_agent' => $ua, 'detail' => $detail, 'last_seen_at' => $now]);
                $event->occurrences = (int)$event->occurrences + 1;
                $event->save();
            } else {
                $event = RiskEvent::create([
                    'fingerprint' => $fingerprint, 'user_id' => $user->id, 'event_type' => $type, 'ip' => $ip,
                    'user_agent' => $ua, 'indicator_ids' => '[]', 'detail' => $detail, 'first_seen_at' => $now,
                    'last_seen_at' => $now, 'occurrences' => 1,
                ]);
            }
        } catch (\Throwable $e) {
            return null;
        }
        if ($alert) {
            $subject = $type === 'register_link' ? 'register:' . $this->access()->ipNet($ip) : null;
            $this->notify($user, $type, $ip, $ua, $detail, (int)$event->id, $subject);
        }
        return $event;
    }

    /**
     * How many alerts were left out today (or on the day of $time) for going over the daily budget of their kind.
     */
    public function skippedAlerts(?int $time = null): int
    {
        return $this->alerts()->dayCounts($time)['skipped'];
    }

    /**
     * The first subscription over the limit each day alerts: how many today, from how many IPs, with which clients.
     */
    private function limitAlert(User $user, Request $request, int $count): void
    {
        try {
            if (!Cache::add('risk:sub-alerted:' . (int)$user->id . ':' . date('Ymd'), 1, 2 * 86400)) return;
            $detail = "今天第 {$count} 次（上限 {$this->access()->dailyLimit()}）· " . $this->todaysClients($user);
            $this->recordFinding($user, 'sub_limit', $this->clientIp($request), (string)$request->header('User-Agent', ''), $detail,
                'sub_limit|' . (int)$user->id . '|' . date('Ymd'));
        } catch (\Throwable $e) {
            // An alert must never change the answer
        }
    }

    /**
     * The first time each day the user's subscriptions in 10 minutes reach sub_burst_limit (订阅过频): how many, and
     * today's IPs and clients.
     */
    private function burstAlert(User $user, Request $request, int $count): void
    {
        try {
            if (!Cache::add('risk:sub-burst-alerted:' . (int)$user->id . ':' . date('Ymd'), 1, 2 * 86400)) return;
            $detail = "10 分钟内 {$count} 次（{$this->access()->burstLimit()} 次起报）· 今天 " . $this->todaysClients($user);
            $this->recordFinding($user, 'sub_burst', $this->clientIp($request), (string)$request->header('User-Agent', ''), $detail,
                'sub_burst|' . (int)$user->id . '|' . date('Ymd'));
        } catch (\Throwable $e) {
            // An alert must never change the answer
        }
    }

    /**
     * The user's subscriptions today for an alert: N 个 IP · 客户端 the three clients used most, with how many times.
     */
    private function todaysClients(User $user): string
    {
        $rows = RiskAccess::where('record_at', $this->access()->day(time()))->where('user_id', $user->id)
            ->where('event_type', RiskAccessService::TYPES['subscription'])->get(['ip_net', 'ua_hash', 'user_agent', 'occurrences']);
        $clients = $rows->groupBy('ua_hash')->map(function ($rows) {
            return ['ua' => (string)$rows->first()->user_agent, 'total' => (int)$rows->sum('occurrences')];
        })->sortByDesc('total')->take(3)->map(function ($client) {
            $ua = trim(preg_replace('/\s+/', ' ', $client['ua']));
            return ($ua === '' ? '空 UA' : mb_substr($ua, 0, 30, 'UTF-8')) . ' ×' . $client['total'];
        })->implode('、');
        return $rows->pluck('ip_net')->filter()->unique()->count() . ' 个 IP · 客户端 ' . $clients;
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
        if ($count === 1) $this->notify($user, $eventType, $ip, $ua, $matches, (int)$event->id, $this->alerts()->requestSubject($user, $ip));
    }

    /**
     * Send a risk alert to the alert chat; with a user and an event it carries the risk bot's action buttons.
     * $matches: the indicators matched, or for a finding (FINDING_TYPES) its detail. With a $subject, the alert is merged
     * into the day's first one about it, and each kind of alert has a daily budget (RiskAlertService).
     */
    public function notify(?User $user, string $eventType, string $ip, string $ua, $matches = [], ?int $eventId = null, ?string $subject = null): void
    {
        $ua = $this->cleanUserAgent($ua, 240);
        $chatId = RiskSettings::get('alert_chat_id');
        if (!$chatId) return;
        $plan = $user && $user->plan_id ? Plan::find($user->plan_id) : null;
        $rules = is_array($matches)
            ? implode(',', array_map(function ($m) { return $m->type . ':' . $m->value; }, $matches))
            : (string)$matches;
        $finding = self::FINDING_TYPES[$eventType] ?? null;
        $escape = function ($value): string {
            return preg_replace_callback('/[_*\[\]()~`>#+\-=|{}.!\\\\]/', function ($match) {
                return '\\' . $match[0];
            }, (string)$value);
        };
        $code = function ($value): string {
            return '`' . str_replace(['\\', '`'], ['\\\\', '\\`'], (string)$value) . '`';
        };
        $text = "*\\[RISK\\]* _" . $escape($finding ?? $eventType) . "_\nuid: `" . ($user ? (int)$user->id : '-') . "`" .
            "\nemail: " . $code($user ? $user->email : '-') . "\nip: " . $code($ip) . "\nua: " . $code($ua) .
            "\nplan: " . $code($plan ? $plan->name : '-') . "\ngroup: " . $code($user ? $user->group_id : '-') .
            ($finding ? "\ndetail: " : "\nrules: ") . $code($rules);
        $token = (string)RiskSettings::get('bot_token');
        if (!$token) return;
        try {
            $state = $subject !== null ? $this->alerts()->gate($subject, $eventId, $user ? (int)$user->id : null) : 'first';
            if ($state === 'merged' || $state === 'closed') return;
            if ($state === 'remind') {
                $text = $escape('🔔 今天又有 ' . RiskAlertService::REMIND_AT . ' 条合并进了被回复的那条告警，这是最新的一条') . "\n" . $text;
            } else {
                $kind = $finding ? $eventType : ($user && (int)$user->risk_status === self::STATUS_RISK ? 'isolated' : 'hit');
                if (!$this->alerts()->withinBudget($kind, $chatId)) return;
            }
            SendRiskTelegramJob::dispatch((int)$chatId, $text, $ip, $user ? (int)$user->id : null, $eventId, $subject, $state === 'remind');
        } catch (\Throwable $e) { /* queue unavailable */ }
    }

    /**
     * Add indicators of a type, as the admin panel and the risk bot do. Returns the values grouped as added, existing
     * (already enabled), invalid, allowlisted (IP indicators an allowlist entry covers, not added) and disabled (IP
     * indicators that the added allowlist entries cover). A disabled indicator added again keeps its note unless
     * $note is given.
     */
    public function addIndicators(string $type, array $values, ?string $note = null): array
    {
        $result = ['added' => [], 'existing' => [], 'invalid' => [], 'allowlisted' => [], 'disabled' => []];
        foreach ($values as $rawValue) {
            $value = $this->normalizeIndicatorValue($type, $rawValue);
            if ($value === null) {
                $result['invalid'][] = trim((string)$rawValue);
                continue;
            }
            $indicator = RiskIndicator::where('type', $type)->where('value', $value)->first();
            if ($indicator && $indicator->enabled) {
                $result['existing'][] = $value;
                continue;
            }
            try {
                $this->addIndicator($type, $value, $note ?? ($indicator ? $indicator->note : null), $disabled);
            } catch (RiskIpAllowlistedException $e) {
                $result['allowlisted'][] = $value;
                continue;
            }
            $result['added'][] = $value;
            $result['disabled'] = array_merge($result['disabled'], $disabled);
        }
        return $result;
    }

    /**
     * Add an indicator or enable it again; see saveIndicatorChecked() for how it is kept apart from the allowlist.
     */
    public function addIndicator(string $type, string $value, ?string $note = null, ?array &$disabled = null): RiskIndicator
    {
        $normalized = $this->normalizeIndicatorValue($type, $value);
        if ($normalized === null) throw new \InvalidArgumentException("Invalid {$type} indicator: {$value}");
        $value = $normalized;
        $indicator = RiskIndicator::firstOrNew(['type' => $type, 'value' => $value]);
        // Adding an indicator that is already enabled only changes its note
        $action = $indicator->exists && $indicator->enabled ? 'edit' : 'add';
        $indicator->fill(['note' => $note, 'enabled' => 1]);
        $this->saveIndicatorChecked($indicator, $action, $disabled);
        if ($type === 'email') {
            User::whereRaw('LOWER(TRIM(email)) = ?', [$value])->get()->each(function ($user) use ($indicator) {
                $this->reconcileEmailRisk($user);
            });
        }
        return $indicator;
    }

    public function updateIndicator(RiskIndicator $indicator, array $attributes, ?array &$disabled = null): bool
    {
        $indicator->fill($attributes);
        $ok = $this->saveIndicatorChecked($indicator, 'edit', $disabled);
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

    /**
     * Save an indicator, keeping the IP list and the allowlist apart when it is added, enabled again or given a new
     * value (a new note alone changes nothing): an IP indicator that an enabled allowlist entry covers is refused
     * with RiskIpAllowlistedException, and an allowlist entry disables the IP indicators it covers, whose values go
     * to $disabled. IP ranges larger than an allowlist entry stay: the entry lets its part of them through.
     */
    private function saveIndicatorChecked(RiskIndicator $indicator, string $action, ?array &$disabled): bool
    {
        $disabled = [];
        $takesEffect = $indicator->enabled && (!$indicator->exists || $indicator->isDirty(['value', 'enabled']));
        if ($takesEffect && $indicator->type === 'ip') {
            $entry = $this->allowEntryFor($indicator->value);
            if ($entry) throw new RiskIpAllowlistedException($indicator->value, $entry);
        }
        if (!$this->saveIndicator($indicator, $action)) return false;
        if ($takesEffect && $indicator->type === 'allow_ip') $disabled = $this->disableIpsCoveredBy($indicator);
        return true;
    }

    /**
     * Disable the enabled IP indicators that the allowlist entry covers. Returns their values.
     */
    private function disableIpsCoveredBy(RiskIndicator $entry): array
    {
        $disabled = [];
        foreach (RiskIndicator::where('type', 'ip')->where('enabled', 1)->orderBy('id')->get() as $indicator) {
            if (!$this->ipRangeWithin($indicator->value, $entry->value)) continue;
            $indicator->enabled = 0;
            if ($this->saveIndicator($indicator, 'delete', "被 IP 白名单 {$entry->value} 覆盖")) $disabled[] = $indicator->value;
        }
        return $disabled;
    }

    /**
     * $reason: why the system made the change, audited with it, e.g. an IP indicator disabled by an allowlist entry.
     */
    private function saveIndicator(RiskIndicator $indicator, string $action, ?string $reason = null): bool
    {
        $changes = $this->changes($indicator, ['value', 'note', 'enabled']);
        if (!$changes) return true;
        if (!$indicator->save()) return false;
        Cache::forget(self::INDICATORS_CACHE_KEY);
        if ($reason !== null) $changes['reason'] = $reason;
        $this->audit($action, $indicator, $changes);
        return true;
    }

    private function saveUserRisk(User $user, ?RiskIndicator $indicator): void
    {
        $changes = $this->changes($user, ['risk_status', 'risk_indicator_id']);
        $user->save();
        if ($changes) $this->audit($user->risk_status ? 'mark' : 'unmark', $indicator, $changes, $user);
        // Isolated from the bot or the admin panel: no more alerts about the user today. One marked by the system (an
        // email indicator matched at registration or login) still alerts.
        if (isset($changes['risk_status']) && $user->risk_status && $this->actor['type'] !== 'system') {
            $this->alerts()->close($this->alerts()->requestSubject($user, ''));
        }
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
    public function cleanUserAgent($ua, int $length): string
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
