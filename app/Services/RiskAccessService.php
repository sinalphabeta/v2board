<?php

namespace App\Services;

use App\Models\RiskAccess;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;

/**
 * The access log (v2_risk_access): every login, registration, subscription and order, one row per day (record_at, the
 * day's 0:00), user, type, result, IP and user agent, kept for access_log_days days; also subscriptions with a link that
 * a reset replaced (old_link, logged for the user it belonged to). Also the daily subscription limit, and the exit IPs
 * of the nodes, which the link checks leave out.
 *
 * An IPv6 address is merged by its /64 (ip_net), since clients rotate their addresses; ip keeps the last one seen.
 * Rows are written one statement each, outside any transaction; a write never fails the request: errors are reported at
 * most every 10 minutes and shown on /health.
 */
class RiskAccessService
{
    public const TYPES = ['subscription' => 1, 'login' => 2, 'register' => 3, 'order' => 4, 'old_link' => 5];
    public const TYPE_NAMES = ['subscription' => '订阅', 'login' => '登录', 'register' => '注册', 'order' => '下单', 'old_link' => '旧链接'];
    /**
     * ok; failed: a wrong password; isolated: the honeypot nodes, or isolated on registration; unavailable: banned,
     * expired or without a plan (no nodes); limited: over the daily limit (answered 429)
     */
    public const RESULTS = ['ok' => 0, 'failed' => 1, 'isolated' => 2, 'unavailable' => 3, 'limited' => 4];
    // After this many subscriptions in a day, a user's new IP and user agent combinations go into one row (ip_net ''):
    // a client may send a new user agent each time
    public const OVERFLOW_AFTER = 1000;
    public const NODE_DAYS = 7;
    // How long a subscription token replaced by a reset is still known (old_link)
    public const OLD_LINK_DAYS = 30;
    private const NODES_KEY = 'risk:node-ips';
    private const ERROR_KEY = 'risk:access:last-error';
    private $risk;

    public function __construct(?RiskService $risk = null)
    {
        $this->risk = $risk;
    }

    public function enabled(): bool
    {
        return (bool)RiskSettings::get('access_log_enabled');
    }

    /**
     * Record a request as $type (a key of TYPES) with $result (a key of RESULTS).
     * $count: the user's subscriptions (or old_link requests) today, for the overflow row.
     */
    public function record(User $user, string $type, Request $request, string $result = 'ok', int $count = 0): void
    {
        if (!isset(self::TYPES[$type], self::RESULTS[$result])) return;
        try {
            if (!$this->enabled()) return;
            $ip = $this->ip($this->risk()->clientIp($request));
            $ua = $this->risk()->cleanUserAgent($request->header('User-Agent', ''), 512);
            $overflow = in_array($type, ['subscription', 'old_link'], true) && $count > self::OVERFLOW_AFTER;
            $now = time();
            DB::insert('INSERT INTO `v2_risk_access` (`record_at`, `user_id`, `event_type`, `result`, `ip_net`, `ua_hash`, `ip`,'
                . ' `user_agent`, `occurrences`, `first_seen_at`, `last_seen_at`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)'
                . ' ON DUPLICATE KEY UPDATE `occurrences` = `occurrences` + 1, `last_seen_at` = VALUES(`last_seen_at`),'
                . ' `ip` = VALUES(`ip`), `user_agent` = VALUES(`user_agent`)', [
                $this->day($now), (int)$user->id, self::TYPES[$type], self::RESULTS[$result],
                $overflow ? '' : $this->ipNet($ip), $overflow ? 0 : crc32($ua), $ip, $ua, $now, $now,
            ]);
        } catch (\Throwable $e) {
            $this->failed($e);
        }
    }

    /**
     * A reset replaced the user's subscription token: keep the old one for OLD_LINK_DAYS days, so that the clients
     * still updating with it (the user's own, or whoever it was shared with) are logged as old_link.
     */
    public function rememberOldToken(string $token, User $user): void
    {
        if ($token === '') return;
        try { Cache::put('risk:old-token:' . sha1($token), (int)$user->id, self::OLD_LINK_DAYS * 86400); } catch (\Throwable $e) { }
    }

    /**
     * A subscription with a token no user has (answered 403 by the client middleware): if a reset replaced it, log it
     * as old_link for the user it belonged to (answered 403 all the same, so 'unavailable').
     */
    public function recordOldLink(string $token, Request $request): void
    {
        try {
            if ($token === '' || !$this->enabled()) return;
            $userId = (int)Cache::get('risk:old-token:' . sha1($token), 0);
            $user = $userId ? User::find($userId) : null;
            if (!$user) return;
            $key = 'risk:old-count:' . $userId . ':' . date('Ymd');
            Cache::add($key, 0, 2 * 86400);
            $this->record($user, 'old_link', $request, 'unavailable', (int)Cache::increment($key));
        } catch (\Throwable $e) {
            // Must never change the answer
        }
    }

    /**
     * Old links of the user in the last OLD_LINK_DAYS days: [requests, IPs (an IPv6 /64 as one), last time], or null.
     */
    public function oldLinks(User $user): ?array
    {
        $row = RiskAccess::where('user_id', $user->id)->where('event_type', self::TYPES['old_link'])
            ->where('record_at', '>=', $this->day(time()) - (self::OLD_LINK_DAYS - 1) * 86400)
            ->selectRaw('SUM(occurrences) AS total, COUNT(DISTINCT ip_net) AS ips, MAX(last_seen_at) AS last_seen_at')->first();
        return $row && (int)$row->total ? [(int)$row->total, (int)$row->ips, (int)$row->last_seen_at] : null;
    }

    /**
     * Count a subscription: how many the user has made today, or 0 if Redis is down (nothing is limited then).
     */
    public function countSubscription(User $user): int
    {
        try {
            $key = $this->countKey($user);
            // add() is atomic and sets the expiry, which increment() alone would not
            Cache::add($key, 0, 2 * 86400);
            return (int)Cache::increment($key);
        } catch (\Throwable $e) {
            return 0;
        }
    }

    public function subscriptionsToday(User $user): int
    {
        try {
            return (int)Cache::get($this->countKey($user), 0);
        } catch (\Throwable $e) {
            return 0;
        }
    }

    public function dailyLimit(): int
    {
        return max(0, (int)RiskSettings::get('sub_daily_limit'));
    }

    /**
     * Whether the user's $count-th subscription today goes over the daily limit. Isolated users never do (they keep
     * getting the honeypot nodes), nor users let through for today.
     */
    public function overLimit(User $user, int $count): bool
    {
        $limit = $this->dailyLimit();
        if ($limit <= 0 || $count <= $limit) return false;
        if ((int)$user->risk_status === RiskService::STATUS_RISK) return false;
        return !$this->exempt($user);
    }

    /**
     * Whether the user is let through for today (今天放行).
     */
    public function exempt(User $user): bool
    {
        try {
            return (bool)Cache::get($this->exemptKey($user));
        } catch (\Throwable $e) {
            return false;
        }
    }

    public function exemptToday(User $user): void
    {
        Cache::put($this->exemptKey($user), 1, max(60, strtotime('tomorrow') - time() + 60));
    }

    /**
     * The answer to a subscription over the limit: clients report a failed update and keep the nodes they have.
     */
    public function limitResponse()
    {
        return response('今日订阅更新次数已达上限，请明天再试', 429, [
            'Content-Type' => 'text/plain; charset=UTF-8',
            'Retry-After' => (string)max(1, strtotime('tomorrow') - time()),
        ]);
    }

    /**
     * Remember the IP a node calls the panel from, after its token is checked: the node's exit IP, which users who
     * update their subscriptions through the node also come from. Kept for NODE_DAYS days.
     */
    public function rememberNode(Request $request): void
    {
        try {
            $ip = $this->ip($this->risk()->clientIp($request));
            if (!$this->isPublic($ip)) return;
            $net = $this->ipNet($ip);
            $now = time();
            $nodes = $this->nodeNets();
            // Nodes call every minute or so: write at most once an hour per IP
            if (isset($nodes[$net]) && $nodes[$net] > $now - 3600) return;
            $nodes[$net] = $now;
            Cache::forever(self::NODES_KEY, $nodes);
        } catch (\Throwable $e) {
            // Must never break a node's request
        }
    }

    /**
     * The nodes' exit IPs (an IPv6 address as its /64) seen in the last NODE_DAYS days, as [ip_net => last seen].
     */
    public function nodeNets(): array
    {
        try {
            $nodes = Cache::get(self::NODES_KEY);
        } catch (\Throwable $e) {
            return [];
        }
        if (!is_array($nodes)) return [];
        $since = time() - self::NODE_DAYS * 86400;
        return array_filter($nodes, function ($seen) use ($since) { return (int)$seen > $since; });
    }

    /**
     * What an IP is merged by: the IP itself, or for IPv6 its /64 (e.g. 2001:db8:1:2::/64).
     */
    public function ipNet(string $ip): string
    {
        $ip = $this->ip($ip);
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) return $ip;
        return $this->risk()->normalizeIndicatorValue('ip', "{$ip}/64") ?? $ip;
    }

    public function isPublic(string $ip): bool
    {
        return (bool)filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE);
    }

    /**
     * The 0:00 (in the app's time zone) of the day of $time.
     */
    public function day(int $time): int
    {
        return strtotime(date('Y-m-d', $time));
    }

    /**
     * A user's rows of a type, the newest first: [rows, page, pages, total].
     */
    public function userPage(User $user, string $type, int $page, int $size): array
    {
        $query = RiskAccess::where('user_id', $user->id)->where('event_type', self::TYPES[$type] ?? 0);
        $total = (clone $query)->count();
        $pages = max(1, (int)ceil($total / $size));
        $page = min(max(1, $page), $pages);
        $rows = $query->orderByDesc('record_at')->orderByDesc('last_seen_at')->forPage($page, $size)->get();
        return [$rows, $page, $pages, $total];
    }

    /**
     * Where the user registered from, if they registered after the access log began.
     */
    public function registration(User $user): ?RiskAccess
    {
        return RiskAccess::where('user_id', $user->id)->where('event_type', self::TYPES['register'])
            ->orderBy('record_at')->orderBy('first_seen_at')->first();
    }

    /**
     * The users of these IPs (or /64s) in the last $days days, by IP as given: [ip => [user_id => [type => count, …,
     * 'last_seen_at' => time]]]. Only from the access log; RiskService::ipUsage() adds the older risk events.
     */
    public function usage(array $ips, int $days): array
    {
        $nets = [];
        foreach (array_unique(array_filter($ips, 'strlen')) as $ip) $nets[$ip] = strpos($ip, '/') !== false ? $ip : $this->ipNet($ip);
        if (!$nets) return [];
        $rows = RiskAccess::whereIn('ip_net', array_values(array_unique($nets)))->where('record_at', '>=', $this->day(time()) - ($days - 1) * 86400)
            ->selectRaw('ip_net, user_id, event_type, SUM(occurrences) AS total, MAX(last_seen_at) AS last_seen_at')
            ->groupBy('ip_net', 'user_id', 'event_type')->get();
        $types = array_flip(self::TYPES);
        $byNet = [];
        foreach ($rows as $row) {
            $entry = &$byNet[$row->ip_net][(int)$row->user_id];
            $type = $types[(int)$row->event_type] ?? 'subscription';
            $entry[$type] = ($entry[$type] ?? 0) + (int)$row->total;
            $entry['last_seen_at'] = max((int)($entry['last_seen_at'] ?? 0), (int)$row->last_seen_at);
            unset($entry);
        }
        $usage = [];
        foreach ($nets as $ip => $net) $usage[$ip] = $byNet[$net] ?? [];
        return $usage;
    }

    /**
     * For /health and the access log page: today's numbers, the table's size (InnoDB's estimate) and the last error.
     */
    public function stats(): array
    {
        $today = $this->day(time());
        $sums = RiskAccess::where('record_at', $today)
            ->selectRaw('event_type, result, COUNT(*) AS row_count, SUM(occurrences) AS total, MAX(last_seen_at) AS last_seen_at')
            ->groupBy('event_type', 'result')->get();
        $count = function (string $type, ?string $result = null) use ($sums) {
            return (int)$sums->filter(function ($row) use ($type, $result) {
                return (int)$row->event_type === self::TYPES[$type] && ($result === null || (int)$row->result === self::RESULTS[$result]);
            })->sum('total');
        };
        $ips = RiskAccess::where('record_at', $today)->pluck('ip');
        $private = $ips->filter(function ($ip) { return !$this->isPublic((string)$ip); })->count();
        try {
            $table = DB::selectOne('SELECT TABLE_ROWS AS row_count, DATA_LENGTH + INDEX_LENGTH AS bytes FROM information_schema.TABLES'
                . ' WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ?', ['v2_risk_access']);
        } catch (\Throwable $e) {
            $table = null;
        }
        try {
            $errors = (int)Cache::get('risk:access:errors:' . date('Ymd'), 0);
            $lastError = Cache::get(self::ERROR_KEY);
        } catch (\Throwable $e) {
            [$errors, $lastError] = [0, null];
        }
        return [
            'enabled' => $this->enabled(),
            'days' => (int)RiskSettings::get('access_log_days'),
            'active_users' => RiskAccess::where('record_at', $today)->where('event_type', self::TYPES['subscription'])->distinct()->count('user_id'),
            'subscriptions' => $count('subscription'),
            'logins' => $count('login', 'ok'),
            'failed_logins' => $count('login', 'failed'),
            'registrations' => $count('register'),
            'orders' => $count('order'),
            'rows_today' => (int)$sums->sum('row_count'),
            'private_rows_today' => $private,
            'last_write_at' => $sums->count() ? (int)$sums->max('last_seen_at') : null,
            'table_rows' => $table ? (int)$table->row_count : null,
            'table_bytes' => $table ? (int)$table->bytes : null,
            'errors_today' => $errors,
            'last_error' => is_array($lastError) ? $lastError : null,
            'nodes' => count($this->nodeNets()),
            'daily_limit' => $this->dailyLimit(),
        ];
    }

    /**
     * Delete the rows older than $days days (today counts as one), 5000 at a time.
     */
    public function prune(int $days): int
    {
        $before = $this->day(time()) - (max(1, $days) - 1) * 86400;
        $total = 0;
        do {
            $deleted = DB::delete('DELETE FROM `v2_risk_access` WHERE `record_at` < ?'
                . ' ORDER BY `record_at`, `user_id`, `event_type`, `result`, `ip_net`, `ua_hash` LIMIT 5000', [$before]);
            $total += $deleted;
            if ($deleted === 5000) usleep(100000);
        } while ($deleted === 5000);
        return $total;
    }

    /**
     * An IPv4 address that came as IPv4-mapped IPv6 (::ffff:1.2.3.4), as IPv4.
     */
    private function ip(string $ip): string
    {
        if (stripos($ip, '::ffff:') === 0 && filter_var(substr($ip, 7), FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) return substr($ip, 7);
        return $ip;
    }

    private function failed(\Throwable $e): void
    {
        try {
            Cache::put(self::ERROR_KEY, ['at' => time(), 'message' => mb_substr($e->getMessage(), 0, 300, 'UTF-8')], 7 * 86400);
            $key = 'risk:access:errors:' . date('Ymd');
            Cache::add($key, 0, 2 * 86400);
            Cache::increment($key);
            if (Cache::add('risk:access:reported', 1, 600)) report($e);
        } catch (\Throwable $ignored) {
            // Redis is down as well
        }
    }

    private function countKey(User $user): string
    {
        return 'risk:sub-count:' . (int)$user->id . ':' . date('Ymd');
    }

    private function exemptKey(User $user): string
    {
        return 'risk:sub-exempt:' . (int)$user->id . ':' . date('Ymd');
    }

    private function risk(): RiskService
    {
        if (!$this->risk) $this->risk = new RiskService();
        return $this->risk;
    }
}
