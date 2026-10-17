<?php

namespace App\Services;

use App\Models\RiskConn;
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
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Redis;

/**
 * The connection log (v2_risk_conn): the IPs users connect to the nodes from, as the nodes report the devices online
 * (UniProxyController::alive(), every minute: the IPs of the connections made since the last report). One row per day
 * (record_at, the day's 0:00), user and IP (an IPv6 address by its /64, ip keeps the last one), with the nodes that
 * reported it (servers, as v2node3), how many reports and the first and last time. Kept conn_log_days days, and for
 * good for the users isolated now.
 *
 * A node IP (a relay's address, seen by a node behind it) is no user's: it is left out, except for isolated users,
 * whose rows are all kept. Private and reserved IPs are left out.
 *
 * The reports go to a Redis list and risk:conn-flush writes them every minute in one statement: the nodes report at the
 * same moment (one writer has no lock waits), and while update.sh runs the new code before the table exists (a batch
 * that fails stays for the next run).
 */
class RiskConnService
{
    // A user's sources a day; later ones go into one row (ip_net ''). An isolated user's are the probing IPs: more
    public const DAILY_SOURCES = 500;
    public const ISOLATED_DAILY_SOURCES = 5000;
    // Online: reported in the last 3 minutes (the nodes report every minute by default)
    public const ONLINE_SECONDS = 180;
    // A source that this many users not isolated connected from in SHARED_DAYS days is shared (a relay not in the node
    // IPs yet, a carrier's NAT, an office): the checks leave it out
    public const SHARED_USERS = 5;
    public const SHARED_DAYS = 7;
    // Filtering by place looks up where this many sources are at most (500 take about 25 ms): it is not stored
    public const PLACE_LOOKUPS = 10000;
    private const BUFFER_KEY = 'risk:conn:buffer';
    private const FLUSHING_KEY = 'risk:conn:flushing';
    // The reports kept while none are written: half an hour to an hour of dozens of nodes'
    private const BUFFER_MAX = 2000;
    // The nodes listed in a row, up to about this many characters
    private const SERVERS_LENGTH = 240;
    private const ERROR_KEY = 'risk:conn:last-error';
    private const FLUSHED_KEY = 'risk:conn:flushed-at';
    // The node types of the servers lists (UniProxyController's node_type, v2node for all the panel's nodes)
    private const MODELS = [
        'v2node' => ServerV2node::class, 'vmess' => ServerVmess::class, 'vless' => ServerVless::class, 'trojan' => ServerTrojan::class,
        'shadowsocks' => ServerShadowsocks::class, 'tuic' => ServerTuic::class, 'hysteria' => ServerHysteria::class, 'anytls' => ServerAnytls::class,
    ];
    private $risk;

    public function __construct(?RiskService $risk = null)
    {
        $this->risk = $risk;
    }

    public function enabled(): bool
    {
        return (bool)RiskSettings::get('conn_log_enabled');
    }

    /**
     * Keep a node's report of the devices online ({uid: [ip, …]}, as it came: with the node IPs) for risk:conn-flush.
     * $server: the node, as the cache keys name it (v2node3).
     */
    public function buffer(string $server, int $time, array $data): void
    {
        try {
            if (!$data || !$this->enabled()) return;
            $redis = Redis::connection();
            $redis->rpush(self::BUFFER_KEY, json_encode(['s' => $server, 't' => $time, 'd' => $data]));
            $redis->ltrim(self::BUFFER_KEY, -self::BUFFER_MAX, -1);
        } catch (\Throwable $e) {
            // Must never break a node's report
        }
    }

    /**
     * risk:conn-flush, every minute: write the buffered reports. A batch that fails (no table yet, the database down)
     * is kept and written first next time, and the error is thrown. Returns how many value rows were written.
     */
    public function flush(): int
    {
        $redis = Redis::connection();
        $written = 0;
        // The batch a failed run left, then the reports since
        for ($i = 0; $i < 2; $i++) {
            if (!$redis->exists(self::FLUSHING_KEY)) {
                if (!$redis->exists(self::BUFFER_KEY)) break;
                $redis->rename(self::BUFFER_KEY, self::FLUSHING_KEY);
            }
            try {
                $written += $this->write($redis->lrange(self::FLUSHING_KEY, 0, -1));
            } catch (\Throwable $e) {
                $this->failed($e);
                throw $e;
            }
            $redis->del(self::FLUSHING_KEY);
            try { Cache::forever(self::FLUSHED_KEY, time()); } catch (\Throwable $e) { }
        }
        return $written;
    }

    /**
     * Merge reports (as buffered) into rows of the day, user, source and node, and write them.
     */
    public function write(array $items): int
    {
        $reports = $userIds = [];
        foreach ($items as $item) {
            $report = json_decode((string)$item, true);
            if (!is_array($report) || !is_array($report['d'] ?? null) || (int)($report['t'] ?? 0) <= 0) continue;
            $report['s'] = substr((string)($report['s'] ?? ''), 0, 32);
            if ($report['s'] === '') continue;
            $reports[] = $report;
            foreach (array_keys($report['d']) as $uid) if (ctype_digit((string)$uid)) $userIds[(int)$uid] = true;
        }
        if (!$reports) return 0;
        $isolated = User::whereIn('id', array_keys($userIds))->where('risk_status', RiskService::STATUS_RISK)->pluck('id')->flip()->all();
        $access = $this->access();
        $isNode = $access->cachedNodeMatcher();
        $rows = [];
        foreach ($reports as $report) {
            $time = (int)$report['t'];
            $day = $access->day($time);
            foreach ($report['d'] as $uid => $ips) {
                if (!ctype_digit((string)$uid) || !is_array($ips)) continue;
                $uid = (int)$uid;
                // A report counts once for a source, however many of its /64's addresses it has
                $counted = [];
                foreach ($ips as $ip) {
                    // Older nodes send ip_nodeid
                    $ip = is_string($ip) ? RiskAccessService::plainIp(trim(explode('_', $ip)[0])) : '';
                    if (!$this->usable($ip)) continue;
                    // A relay's address is no user's; an isolated user's are kept all the same (shown as 节点)
                    if (!isset($isolated[$uid]) && $isNode($ip)) continue;
                    $net = $access->ipNet($ip);
                    if (isset($counted[$net])) continue;
                    $counted[$net] = true;
                    $key = "{$day}|{$uid}|{$net}|{$report['s']}";
                    if (!isset($rows[$key])) {
                        $rows[$key] = ['record_at' => $day, 'user_id' => $uid, 'ip_net' => $net, 'ip' => $ip, 'server' => $report['s'],
                            'reports' => 0, 'first_seen_at' => $time, 'last_seen_at' => $time];
                    }
                    $row = &$rows[$key];
                    $row['reports']++;
                    $row['first_seen_at'] = min($row['first_seen_at'], $time);
                    if ($time >= $row['last_seen_at']) {
                        $row['last_seen_at'] = $time;
                        $row['ip'] = $ip;
                    }
                    unset($row);
                }
            }
        }
        $rows = $this->capped(array_values($rows), $isolated);
        foreach (array_chunk($rows, 500) as $chunk) {
            $bindings = [];
            foreach ($chunk as $row) {
                array_push($bindings, $row['record_at'], $row['user_id'], $row['ip_net'], $row['ip'], $row['server'], $row['reports'],
                    $row['first_seen_at'], $row['last_seen_at']);
            }
            DB::insert('INSERT INTO `v2_risk_conn` (`record_at`, `user_id`, `ip_net`, `ip`, `servers`, `reports`, `first_seen_at`,'
                . ' `last_seen_at`) VALUES ' . implode(', ', array_fill(0, count($chunk), '(?, ?, ?, ?, ?, ?, ?, ?)'))
                // A value row has one node: the row's list gets it if new and there is room
                . ' ON DUPLICATE KEY UPDATE `servers` = IF(FIND_IN_SET(VALUES(`servers`), `servers`) OR LENGTH(`servers`) > '
                . self::SERVERS_LENGTH . ', `servers`, CONCAT(`servers`, \',\', VALUES(`servers`))),'
                . ' `reports` = `reports` + VALUES(`reports`),'
                // Set in order: ip compares with last_seen_at before it changes
                . ' `ip` = IF(VALUES(`last_seen_at`) >= `last_seen_at`, VALUES(`ip`), `ip`),'
                . ' `first_seen_at` = LEAST(`first_seen_at`, VALUES(`first_seen_at`)),'
                . ' `last_seen_at` = GREATEST(`last_seen_at`, VALUES(`last_seen_at`))', $bindings);
        }
        return count($rows);
    }

    /**
     * The rows with the sources over a user's daily limit (DAILY_SOURCES, ISOLATED_DAILY_SOURCES) moved to the
     * overflow row (ip_net ''); a source the user has a row for today stays in it.
     */
    private function capped(array $rows, array $isolated): array
    {
        $sources = [];
        foreach ($rows as $row) $sources[$row['record_at']][$row['user_id']][$row['ip_net']] = true;
        $over = [];
        foreach ($sources as $day => $users) {
            $counts = RiskConn::where('record_at', $day)->whereIn('user_id', array_keys($users))->where('ip_net', '!=', '')
                ->selectRaw('user_id, COUNT(*) AS total')->groupBy('user_id')->pluck('total', 'user_id');
            foreach ($users as $uid => $nets) {
                $limit = isset($isolated[$uid]) ? self::ISOLATED_DAILY_SOURCES : self::DAILY_SOURCES;
                $have = (int)($counts[$uid] ?? 0);
                if ($have + count($nets) <= $limit) continue;
                $known = RiskConn::where('record_at', $day)->where('user_id', $uid)->pluck('ip_net')->flip()->all();
                $over["{$day}|{$uid}"] = ['known' => $known, 'left' => max(0, $limit - $have)];
            }
        }
        if (!$over) return $rows;
        foreach ($rows as &$row) {
            $pair = "{$row['record_at']}|{$row['user_id']}";
            if (!isset($over[$pair]) || isset($over[$pair]['known'][$row['ip_net']])) continue;
            if ($over[$pair]['left'] > 0) {
                // A new source within the limit: its rows of other nodes go into the same row
                $over[$pair]['left']--;
                $over[$pair]['known'][$row['ip_net']] = true;
                continue;
            }
            $row['ip_net'] = '';
        }
        unset($row);
        return $rows;
    }

    /**
     * The users and sources reported in the last $window seconds by where they are (from the IP's location, only
     * counted): users, ips, provinces ([name, users, ips], the most users first; Hong Kong, Macao and Taiwan each as
     * one), overseas and unknown ([users, ips]).
     */
    public function live(int $window = self::ONLINE_SECONDS): array
    {
        $now = time();
        $rows = RiskConn::whereIn('record_at', array_unique([$this->access()->day($now - $window), $this->access()->day($now)]))
            ->where('last_seen_at', '>=', $now - $window)->where('ip_net', '!=', '')->get(['user_id', 'ip_net', 'ip']);
        $info = $rows->isEmpty() ? [] : (new IpInfoService())->lookupMany($rows->pluck('ip')->unique()->values()->all());
        $places = ['province' => [], 'overseas' => [], 'unknown' => []];
        foreach ($rows as $row) {
            [$kind, $name] = $this->place($info[$row->ip]['location'] ?? null);
            $places[$kind][$name]['users'][$row->user_id] = true;
            $places[$kind][$name]['ips'][$row->ip_net] = true;
        }
        $count = function (array $groups): array {
            $users = $ips = [];
            foreach ($groups as $group) {
                $users += $group['users'];
                $ips += $group['ips'];
            }
            return ['users' => count($users), 'ips' => count($ips)];
        };
        $provinces = [];
        foreach ($places['province'] as $name => $group) {
            $provinces[] = ['name' => (string)$name, 'users' => count($group['users']), 'ips' => count($group['ips'])];
        }
        usort($provinces, function ($a, $b) { return [$b['users'], $b['ips']] <=> [$a['users'], $a['ips']]; });
        return [
            'window' => $window,
            'users' => $rows->pluck('user_id')->unique()->count(),
            'ips' => $rows->pluck('ip_net')->unique()->count(),
            'provinces' => $provinces,
            'overseas' => $count($places['overseas']),
            'unknown' => $count($places['unknown']),
        ];
    }

    /**
     * Where a location (国家 省 市, see IpInfoService) counts: ['province', the province] in China (Hong Kong, Macao
     * and Taiwan as provinces too), ['overseas', the country], or ['unknown', ''] for no location or a private one.
     */
    public function place(?string $location): array
    {
        $parts = preg_split('/\s+/u', trim((string)$location), -1, PREG_SPLIT_NO_EMPTY);
        if (!$parts || $parts[0] === '内网/保留地址' || $parts[0] === '未知') return ['unknown', ''];
        if ($parts[0] !== '中国') return ['overseas', $parts[0]];
        return isset($parts[1]) ? ['province', $parts[1]] : ['unknown', ''];
    }

    /**
     * A place as the admin panel filters by it: the province (see place()), 海外 or 未知.
     */
    public function placeName(?string $location): string
    {
        [$kind, $name] = $this->place($location);
        return $kind === 'province' ? $name : ($kind === 'overseas' ? '海外' : '未知');
    }

    /**
     * The sources of a query's rows in a place (see placeName()), from where their IPs are; null when there are more
     * than PLACE_LOOKUPS of them to look up.
     */
    public function netsIn($query, string $place): ?array
    {
        $rows = (clone $query)->reorder()->where('ip_net', '!=', '')->selectRaw('ip_net, MAX(ip) AS ip')->groupBy('ip_net')
            ->limit(self::PLACE_LOOKUPS + 1)->get();
        if ($rows->count() > self::PLACE_LOOKUPS) return null;
        $info = $rows->isEmpty() ? [] : (new IpInfoService())->lookupMany($rows->pluck('ip')->unique()->values()->all());
        return $rows->filter(function ($row) use ($info, $place) {
            return $this->placeName($info[$row->ip]['location'] ?? null) === $place;
        })->map(function ($row) { return (string)$row->ip_net; })->values()->all();
    }

    /**
     * Sum up a user's rows (of any days) by source: sources, segments (see segment()), brief (sources seen within two
     * minutes only, as a probe's), provinces (with $info, IpInfoService::lookupMany() of their IPs), nodes (the keys
     * of servers), whether some went into the overflow row, and the first and last time.
     */
    public function summarize($rows, array $info = []): array
    {
        $sources = $segments = $provinces = $nodes = [];
        $overflow = false;
        $first = $last = null;
        foreach ($rows as $row) {
            $first = $first === null ? (int)$row->first_seen_at : min($first, (int)$row->first_seen_at);
            $last = $last === null ? (int)$row->last_seen_at : max($last, (int)$row->last_seen_at);
            foreach (array_filter(explode(',', (string)$row->servers)) as $server) $nodes[$server] = true;
            if ((string)$row->ip_net === '') {
                $overflow = true;
                continue;
            }
            $source = &$sources[(string)$row->ip_net];
            $source = [min($source[0] ?? PHP_INT_MAX, (int)$row->first_seen_at), max($source[1] ?? 0, (int)$row->last_seen_at)];
            unset($source);
            $segments[$this->segment((string)$row->ip_net)] = true;
            [$kind, $name] = $this->place($info[$row->ip]['location'] ?? null);
            if ($kind !== 'unknown') $provinces[$kind . $name] = true;
        }
        $brief = count(array_filter($sources, function ($seen) { return $seen[1] - $seen[0] < 120; }));
        return [
            'sources' => count($sources), 'segments' => count($segments), 'brief' => $brief, 'provinces' => count($provinces),
            'nodes' => array_keys($nodes), 'overflow' => $overflow, 'first_seen_at' => $first, 'last_seen_at' => $last,
        ];
    }

    /**
     * The nodes named in servers lists (v2node3, or a protocol and id) with their names (null when deleted) and
     * whether they are honeypot nodes: [key => ['key', 'type', 'id', 'name', 'honeypot']].
     */
    public function servers(array $keys): array
    {
        $byType = [];
        foreach (array_unique($keys) as $key) {
            if (preg_match('/^([a-z][a-z0-9]*?)(\d+)$/', (string)$key, $match)) $byType[$match[1]][(int)$match[2]] = (string)$key;
        }
        $honeypot = (int)RiskSettings::get('honeypot_group_id');
        $servers = [];
        foreach ($byType as $type => $ids) {
            $model = self::MODELS[$type] ?? null;
            $nodes = $model ? $model::whereIn('id', array_keys($ids))->get(['id', 'name', 'group_id'])->keyBy('id') : collect();
            foreach ($ids as $id => $key) {
                $node = $nodes->get($id);
                $groups = $node && is_array($node->group_id) ? array_map('intval', $node->group_id) : [];
                $servers[$key] = ['key' => $key, 'type' => $type, 'id' => $id, 'name' => $node ? (string)$node->name : null,
                    'honeypot' => $honeypot > 0 && in_array($honeypot, $groups, true)];
            }
        }
        return $servers;
    }

    /**
     * risk:scan, every 10 minutes: alert users with many sources in the last hour (conn_ips) and users connecting from
     * the probing IPs (conn_link); each check fails alone. Only alerted, never acted on. Returns how many were alerted.
     */
    public function scan(): int
    {
        if (!$this->enabled()) return 0;
        $alerted = 0;
        foreach (['scanSources', 'scanProbes'] as $check) {
            try {
                $alerted += $this->{$check}();
            } catch (\Throwable $e) {
                report($e);
            }
        }
        return $alerted;
    }

    /**
     * 连接 IP 过多: a user (not isolated, not an admin) with conn_ip_limit or more sources in the last hour, in at
     * least half as many segments (a phone's carrier changes its address within one or two), left-out and shared
     * sources aside. Where they are is only written in the alert.
     */
    private function scanSources(): int
    {
        $limit = (int)RiskSettings::get('conn_ip_limit');
        if ($limit <= 0) return 0;
        $since = time() - 3600;
        $recent = function () use ($since) {
            return RiskConn::whereIn('record_at', array_unique([$this->access()->day($since), $this->access()->day(time())]))
                ->where('last_seen_at', '>=', $since)->where('ip_net', '!=', '');
        };
        $ids = $recent()->groupBy('user_id')->havingRaw('COUNT(DISTINCT ip_net) >= ?', [$limit])->pluck('user_id')->all();
        $users = $ids ? User::whereIn('id', $ids)->where('risk_status', '!=', RiskService::STATUS_RISK)->where('is_admin', 0)->get()->keyBy('id') : collect();
        if (!$users->count()) return 0;
        $rows = $recent()->whereIn('user_id', $users->keys()->all())->get();
        $exclude = $this->risk()->links()->excluder();
        $shared = $this->sharedNets($rows->pluck('ip_net')->unique()->values()->all());
        $alerted = 0;
        foreach ($rows->groupBy('user_id') as $userId => $userRows) {
            $kept = $userRows->reject(function (RiskConn $row) use ($exclude, $shared) {
                return isset($shared[$row->ip_net]) || $exclude((string)$row->ip, (string)$row->ip_net);
            });
            $info = (new IpInfoService())->lookupMany($kept->pluck('ip')->unique()->values()->all());
            $summary = $this->summarize($kept, $info);
            if ($summary['sources'] < $limit || $summary['segments'] < (int)ceil($limit / 2)) continue;
            $networks = $kept->map(function (RiskConn $row) use ($info) { return $info[$row->ip]['network'] ?? null; })->filter()->unique()->count();
            $names = array_filter(array_column($this->servers($summary['nodes']), 'name'));
            $latest = $kept->sortByDesc('last_seen_at');
            $examples = $latest->unique('ip_net')->take(3)->map(function (RiskConn $row) use ($info) {
                return trim($row->ip . ' ' . $this->where($info[$row->ip] ?? null));
            })->implode('、');
            $detail = "1 小时内 {$summary['sources']} 个 IP（{$summary['segments']} 个网段，{$summary['brief']} 个只出现了一两分钟）· "
                . "{$summary['provinces']} 个地区、{$networks} 个运营商 · 节点 " . (implode('、', array_slice($names, 0, 3)) ?: '-') . " · {$examples}";
            if ($this->recordOnce($users->get($userId), 'conn_ips', (string)$latest->first()->ip, $detail)) $alerted++;
        }
        return $alerted;
    }

    /**
     * 命中测活 IP: a user (not isolated, not an admin) connecting today from conn_link_ips or more probing IPs (see
     * probeUsers()); under the link checks' switch.
     */
    private function scanProbes(): int
    {
        $threshold = (int)RiskSettings::get('conn_link_ips');
        if ($threshold <= 0 || !RiskSettings::get('link_detection')) return 0;
        // Today's sources of users not isolated that an isolated user connected from too
        $rows = RiskConn::where('record_at', $this->access()->day(time()))->where('ip_net', '!=', '')
            ->whereNotIn('user_id', User::where('risk_status', RiskService::STATUS_RISK)->select('id'))
            ->whereExists(function ($query) {
                $query->select(DB::raw(1))->from('v2_risk_conn as probe')->join('v2_user as owner', 'owner.id', '=', 'probe.user_id')
                    ->whereColumn('probe.ip_net', 'v2_risk_conn.ip_net')->where('owner.risk_status', RiskService::STATUS_RISK);
            })->get();
        if (!$rows->count()) return 0;
        $probes = $this->probeUsers($rows->pluck('ip_net')->unique()->values()->all());
        $users = User::whereIn('id', $rows->pluck('user_id')->unique()->values())->where('is_admin', 0)->get()->keyBy('id');
        $alerted = 0;
        foreach ($rows->groupBy('user_id') as $userId => $userRows) {
            $hits = $userRows->filter(function (RiskConn $row) use ($probes) { return isset($probes[$row->ip_net]); })->unique('ip_net')->values();
            if (!$users->has($userId) || $hits->count() < $threshold) continue;
            $detail = '今天 ' . $hits->count() . ' 个连接 IP 是测活 IP：' . $hits->take(3)->map(function (RiskConn $row) use ($probes) {
                $by = $probes[$row->ip_net];
                arsort($by);
                $owner = array_key_first($by);
                return $row->ip_net . (strpos($row->ip_net, ':') !== false ? '（IPv6 /64）' : '（IPv4）') .
                    " 被已隔离用户 uid {$owner} 用过，最后 " . date('m-d', $by[$owner]);
            })->implode('；');
            if ($this->recordOnce($users->get($userId), 'conn_link', (string)$hits->first()->ip, $detail)) $alerted++;
        }
        return $alerted;
    }

    /**
     * Record a finding about the user, alerted once in 24 hours (not by the date: a check before and after midnight
     * would alert twice); later scans update the same event quietly. Returns whether it alerted.
     */
    private function recordOnce(User $user, string $type, string $ip, string $detail): bool
    {
        $key = "risk:conn:{$type}:" . (int)$user->id;
        // Which alert the later scans update: its time and a random part, as two may come within a second
        $alerted = time() . ':' . bin2hex(random_bytes(4));
        $alert = Cache::add($key, $alerted, 86400);
        if (!$alert) $alerted = (string)Cache::get($key, $alerted);
        $this->risk()->recordFinding($user, $type, $ip, '', $detail, "{$type}|{$user->id}|{$alerted}", $alert);
        return $alert;
    }

    /**
     * Which of these sources are probing IPs, by whom: [ip_net => [user_id => last seen]] for the sources that users
     * isolated now connected from (ever, their rows are kept), less those left out (allowlisted, node IPs) or shared.
     */
    public function probeUsers(array $nets): array
    {
        if (!$nets) return [];
        $rows = RiskConn::whereIn('ip_net', $nets)->whereIn('user_id', User::where('risk_status', RiskService::STATUS_RISK)->select('id'))
            ->selectRaw('ip_net, user_id, MAX(ip) AS ip, MAX(last_seen_at) AS last_seen_at')->groupBy('ip_net', 'user_id')->get();
        $exclude = $this->risk()->links()->excluder();
        $shared = $this->sharedNets($nets);
        $probes = [];
        foreach ($rows as $row) {
            if (isset($shared[$row->ip_net]) || $exclude((string)$row->ip, (string)$row->ip_net)) continue;
            $probes[(string)$row->ip_net][(int)$row->user_id] = (int)$row->last_seen_at;
        }
        return $probes;
    }

    /**
     * Which of these sources are shared: [ip_net => users] for SHARED_USERS or more users not isolated in the last
     * SHARED_DAYS days (isolated users not counted: a honeypot node behind the same relay is no reason).
     */
    public function sharedNets(array $nets): array
    {
        if (!$nets) return [];
        return RiskConn::whereIn('ip_net', $nets)->where('record_at', '>=', $this->access()->day(time()) - (self::SHARED_DAYS - 1) * 86400)
            ->whereNotIn('user_id', User::where('risk_status', RiskService::STATUS_RISK)->select('id'))
            ->selectRaw('ip_net, COUNT(DISTINCT user_id) AS users')->groupBy('ip_net')
            ->havingRaw('COUNT(DISTINCT user_id) >= ?', [self::SHARED_USERS])->pluck('users', 'ip_net')->all();
    }

    /**
     * The probing IPs page by page, the latest first: the sources of the users isolated now, each with those users,
     * the nodes, when, how many users not isolated connected from it in the last SHARED_DAYS days, and why it does
     * not count, if so (node: a node IP; allow: allowlisted; shared). $ip: that source only. Returns [rows, total].
     */
    public function probes(int $page, int $size, ?string $ip = null): array
    {
        $isolated = User::where('risk_status', RiskService::STATUS_RISK)->select('id');
        $query = RiskConn::whereIn('user_id', $isolated)->where('ip_net', '!=', '');
        if ($ip !== null) $query->where('ip_net', $this->access()->ipNet($ip));
        $total = (clone $query)->distinct()->count('ip_net');
        $rows = (clone $query)->selectRaw('ip_net, MAX(ip) AS ip, MIN(first_seen_at) AS first_seen_at, MAX(last_seen_at) AS last_seen_at,'
            . ' SUM(reports) AS reports')->groupBy('ip_net')->orderByDesc('last_seen_at')->forPage($page, $size)->get();
        $nets = $rows->pluck('ip_net')->all();
        $owners = $nets ? RiskConn::whereIn('ip_net', $nets)->whereIn('user_id', $isolated)->get(['ip_net', 'user_id', 'servers'])->groupBy('ip_net') : collect();
        $others = $nets ? RiskConn::whereIn('ip_net', $nets)->where('record_at', '>=', $this->access()->day(time()) - (self::SHARED_DAYS - 1) * 86400)
            ->whereNotIn('user_id', $isolated)->selectRaw('ip_net, COUNT(DISTINCT user_id) AS users')->groupBy('ip_net')->pluck('users', 'ip_net') : collect();
        $isNode = $this->access()->nodeMatcher();
        $allowed = [];
        foreach (RiskIndicator::where('type', 'allow_ip')->where('enabled', 1)->get() as $entry) $allowed[] = $entry;
        $data = $rows->map(function ($row) use ($owners, $others, $isNode, $allowed) {
            $mine = $owners->get($row->ip_net, collect());
            $users = (int)($others[$row->ip_net] ?? 0);
            $allow = false;
            foreach ($allowed as $entry) {
                if ($this->risk()->entryMatches((string)$row->ip, $entry) || $this->risk()->ipRangeWithin((string)$row->ip_net, (string)$entry->value)) $allow = true;
            }
            $why = $isNode((string)$row->ip, (string)$row->ip_net) ? 'node' : ($allow ? 'allow' : ($users >= self::SHARED_USERS ? 'shared' : null));
            return [
                'ip_net' => (string)$row->ip_net, 'ip' => (string)$row->ip,
                'users' => $mine->pluck('user_id')->unique()->values()->all(),
                'nodes' => $mine->flatMap(function ($r) { return array_filter(explode(',', (string)$r->servers)); })->unique()->values()->all(),
                'first_seen_at' => (int)$row->first_seen_at, 'last_seen_at' => (int)$row->last_seen_at, 'reports' => (int)$row->reports,
                'others' => $users, 'excluded' => $why,
            ];
        })->all();
        return [$data, $total];
    }

    /**
     * Stop counting a source as a probing IP (删除测活 IP: as when the admin tested the honeypot nodes with an
     * isolated user's subscription): delete its rows of the users isolated now. Returns those users' ids, for the
     * audit log; null when it was not one.
     */
    public function dropProbe(string $ipNet): ?array
    {
        // The overflow row is no source
        if ($ipNet === '') return null;
        $isolated = User::where('risk_status', RiskService::STATUS_RISK)->select('id');
        $users = RiskConn::where('ip_net', $ipNet)->whereIn('user_id', $isolated)->distinct()->pluck('user_id')->all();
        if (!$users) return null;
        RiskConn::where('ip_net', $ipNet)->whereIn('user_id', $users)->delete();
        return array_map('intval', $users);
    }

    /**
     * The user's sources today, for the bot's user card: [sources, segments], or null without any.
     */
    public function today(User $user): ?array
    {
        $nets = RiskConn::where('record_at', $this->access()->day(time()))->where('user_id', $user->id)->where('ip_net', '!=', '')->pluck('ip_net');
        if (!$nets->count()) return null;
        return [$nets->count(), $nets->map(function ($net) { return $this->segment((string)$net); })->unique()->count()];
    }

    /**
     * The user's sources in the last 24 hours, the latest first: [up to $limit rows (one a source), all sources].
     */
    public function recent(User $user, int $limit): array
    {
        $since = time() - 86400;
        $rows = RiskConn::whereIn('record_at', array_unique([$this->access()->day($since), $this->access()->day(time())]))
            ->where('user_id', $user->id)->where('last_seen_at', '>=', $since)->orderByDesc('last_seen_at')->get()->unique('ip_net')->values();
        return [$rows->take($limit)->values(), $rows->count()];
    }

    /**
     * Who connected from these IPs (an IPv6 address by its /64, or a /64 given as such) in the last $days days, by IP
     * as given: [ip => [user_id => ['connect' => reports, 'last_seen_at' => time]]].
     */
    public function usage(array $ips, int $days): array
    {
        $nets = [];
        foreach (array_unique(array_filter($ips, 'strlen')) as $ip) $nets[$ip] = strpos($ip, '/') !== false ? $ip : $this->access()->ipNet($ip);
        if (!$nets) return [];
        $rows = RiskConn::whereIn('ip_net', array_values(array_unique($nets)))->where('record_at', '>=', $this->access()->day(time()) - ($days - 1) * 86400)
            ->selectRaw('ip_net, user_id, SUM(reports) AS total, MAX(last_seen_at) AS last_seen_at')->groupBy('ip_net', 'user_id')->get();
        $usage = [];
        foreach ($nets as $ip => $net) {
            foreach ($rows->where('ip_net', $net) as $row) {
                $usage[$ip][(int)$row->user_id] = ['connect' => (int)$row->total, 'last_seen_at' => (int)$row->last_seen_at];
            }
        }
        return $usage;
    }

    /**
     * The users with the most sources on the day of $time (for the daily report): user_id, sources, segments and
     * provinces (from where the IPs are, only counted), the most sources first. Not the users isolated now (their
     * probing takes hundreds of sources a day) or admins: the list is for setting the thresholds.
     */
    public function top(int $time, int $limit = 5): array
    {
        $day = $this->access()->day($time);
        $ids = RiskConn::where('record_at', $day)->where('ip_net', '!=', '')
            ->whereNotIn('user_id', User::where('risk_status', RiskService::STATUS_RISK)->orWhere('is_admin', 1)->select('id'))
            ->selectRaw('user_id, COUNT(*) AS total')->groupBy('user_id')->orderByDesc('total')->limit($limit)->pluck('user_id')->all();
        if (!$ids) return [];
        $rows = RiskConn::where('record_at', $day)->whereIn('user_id', $ids)->get()->groupBy('user_id');
        $info = (new IpInfoService())->lookupMany($rows->flatten(1)->pluck('ip')->unique()->values()->all());
        $top = [];
        foreach ($ids as $id) {
            $summary = $this->summarize($rows->get($id, collect()), $info);
            $top[] = ['user_id' => (int)$id, 'sources' => $summary['sources'], 'segments' => $summary['segments'], 'provinces' => $summary['provinces']];
        }
        return $top;
    }

    /**
     * Where an IP is in a few words for the alerts (广东 联通): its location without 中国, and its ISP.
     */
    private function where(?array $info): string
    {
        if (!$info) return '';
        return trim(preg_replace('/^中国\s*/u', '', (string)($info['location'] ?? '')) . ' ' . ($info['network'] ?? ''));
    }

    /**
     * Whether an IP is logged: public, and outside the carrier-grade NAT space (100.64.0.0/10), which PHP 8.1 calls
     * public.
     */
    public function usable(string $ip): bool
    {
        return $this->access()->isPublic($ip) && !$this->risk()->ipMatches($ip, '100.64.0.0/10');
    }

    /**
     * The network a source is in, for counting how spread a user's sources are: an IPv4 address's /16, an IPv6 one's
     * /32 (as text: 1.2, 2409:8a55). From the address alone, never from where it is.
     */
    public function segment(string $ipNet): string
    {
        $ip = explode('/', $ipNet)[0];
        if (!filter_var($ip, FILTER_VALIDATE_IP)) return $ipNet;
        $binary = inet_pton($ip);
        if (strlen($binary) === 4) return implode('.', array_slice(explode('.', $ip), 0, 2));
        return bin2hex(substr($binary, 0, 2)) . ':' . bin2hex(substr($binary, 2, 2));
    }

    /**
     * Delete the rows older than $days days (today counts as one), 5000 at a time, except the users' isolated now:
     * their sources are the probing IPs, kept for good. Returns how many were deleted.
     */
    public function prune(int $days): int
    {
        $before = $this->access()->day(time()) - (max(1, $days) - 1) * 86400;
        $total = 0;
        do {
            $deleted = DB::delete('DELETE FROM `v2_risk_conn` WHERE `record_at` < ? AND `user_id` NOT IN'
                . ' (SELECT `id` FROM `v2_user` WHERE `risk_status` = ?) ORDER BY `record_at`, `user_id`, `ip_net` LIMIT 5000',
                [$before, RiskService::STATUS_RISK]);
            $total += $deleted;
            if ($deleted === 5000) usleep(100000);
        } while ($deleted === 5000);
        return $total;
    }

    /**
     * For the connection log page: the buffer, the last write and error, today's rows and the table's size (InnoDB's
     * estimate).
     */
    public function stats(): array
    {
        try {
            $buffered = (int)Redis::connection()->llen(self::BUFFER_KEY) + (int)Redis::connection()->llen(self::FLUSHING_KEY);
            $flushedAt = Cache::get(self::FLUSHED_KEY);
            $lastError = Cache::get(self::ERROR_KEY);
        } catch (\Throwable $e) {
            [$buffered, $flushedAt, $lastError] = [null, null, null];
        }
        try {
            $table = DB::selectOne('SELECT TABLE_ROWS AS row_count, DATA_LENGTH + INDEX_LENGTH AS bytes FROM information_schema.TABLES'
                . ' WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ?', ['v2_risk_conn']);
            $today = RiskConn::where('record_at', $this->access()->day(time()))->count();
        } catch (\Throwable $e) {
            [$table, $today] = [null, null];
        }
        return [
            'enabled' => $this->enabled(),
            'days' => (int)RiskSettings::get('conn_log_days'),
            'buffered' => $buffered,
            'flushed_at' => $flushedAt ? (int)$flushedAt : null,
            'last_error' => is_array($lastError) ? $lastError : null,
            'rows_today' => $today,
            'table_rows' => $table ? (int)$table->row_count : null,
            'table_bytes' => $table ? (int)$table->bytes : null,
        ];
    }

    private function failed(\Throwable $e): void
    {
        try {
            Cache::put(self::ERROR_KEY, ['at' => time(), 'message' => mb_substr($e->getMessage(), 0, 300, 'UTF-8')], 7 * 86400);
            if (Cache::add('risk:conn:reported', 1, 600)) report($e);
        } catch (\Throwable $ignored) {
            // Redis is down as well
        }
    }

    private function risk(): RiskService
    {
        if (!$this->risk) $this->risk = new RiskService();
        return $this->risk;
    }

    private function access(): RiskAccessService
    {
        return $this->risk()->access();
    }
}
