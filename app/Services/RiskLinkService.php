<?php

namespace App\Services;

use App\Models\RiskAccess;
use App\Models\RiskAudit;
use App\Models\RiskEvent;
use App\Models\RiskIndicator;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;

/**
 * Links between accounts found in the access log, alerted as risk events (RiskService::recordFinding()) and never acted
 * on: the admin decides. Private IPs, the IP allowlist and the nodes' exit IPs are left out, as IPs shared by design.
 * Also the numbers of the daily report.
 */
class RiskLinkService
{
    // A registration is checked against this many days: a dynamic IP goes to someone else within weeks
    public const REGISTER_DAYS = 7;
    // An IP already alerted today is alerted again when its users reach this many
    public const IP_USERS_AGAIN = 10;
    // Users with subscriptions from this many places (country and province) in a day are listed in the daily report
    public const REPORT_REGIONS = 3;
    // User agents of scripts rather than proxy clients, for the daily report (an empty one too)
    private const SCRIPT_AGENTS = '^(curl|wget|python|go-http-client|java)';
    private $risk;
    private $access;

    public function __construct(?RiskService $risk = null)
    {
        $this->risk = $risk ?: new RiskService();
        $this->access = $this->risk->access();
    }

    public function enabled(): bool
    {
        return (bool)RiskSettings::get('link_detection') && $this->access->enabled();
    }

    /**
     * At registration (after its access row is written): alert if the IP, or its /64, was used in the last
     * REGISTER_DAYS days by an isolated user (a new account of the same person?), by two or more other new accounts,
     * or by the user who invited this one (inviting oneself for the commission?).
     */
    public function checkRegistration(User $user, Request $request): void
    {
        try {
            if (!$this->enabled()) return;
            $ip = $this->risk->clientIp($request);
            $net = $this->access->ipNet($ip);
            if (($this->excluder())($ip, $net)) return;
            $since = $this->access->day(time()) - (self::REGISTER_DAYS - 1) * 86400;
            $rows = RiskAccess::where('ip_net', $net)->where('record_at', '>=', $since)->where('user_id', '!=', $user->id)
                ->get(['user_id', 'event_type']);
            $isolatedIds = User::where('risk_status', RiskService::STATUS_RISK)->where('id', '!=', $user->id)->pluck('id')->flip();
            $isolated = $rows->pluck('user_id')->filter(function ($id) use ($isolatedIds) { return isset($isolatedIds[$id]); });
            // Isolated users' requests from before the access log began are in their risk events
            $events = RiskEvent::where('last_seen_at', '>=', time() - self::REGISTER_DAYS * 86400)
                ->whereIn('user_id', $isolatedIds->keys()->all())->whereIn('event_type', ['subscription', 'login', 'register'])
                ->get(['user_id', 'ip'])->filter(function (RiskEvent $event) use ($net) {
                    return $this->access->ipNet((string)$event->ip) === $net;
                })->pluck('user_id');
            $isolated = $isolated->merge($events)->unique()->values();
            $registered = $rows->where('event_type', RiskAccessService::TYPES['register'])->pluck('user_id')->unique()->values();
            $found = [];
            if ($isolated->count()) $found[] = '被已隔离用户 ' . $this->uids($isolated->all()) . ' 用过';
            if ($registered->count() >= 2) $found[] = '已注册过 ' . $registered->count() . ' 个其他账号（' . $this->uids($registered->all()) . '）';
            if ($user->invite_user_id && $rows->contains('user_id', (int)$user->invite_user_id)) {
                $found[] = '邀请人 uid ' . (int)$user->invite_user_id . ' 也用过';
            }
            if (!$found) return;
            $this->risk->recordFinding($user, 'register_link', $ip, (string)$request->header('User-Agent', ''),
                '注册 IP ' . self::REGISTER_DAYS . ' 天内' . implode('；', $found), 'register_link|' . (int)$user->id);
        } catch (\Throwable $e) {
            // A check must never fail the registration
        }
    }

    /**
     * risk:scan, every 10 minutes: IPs (an IPv6 /64) with link_ip_users or more users today subscribing or logged in
     * (two are enough when one of them is isolated), alerted once a day each and again when their users reach
     * IP_USERS_AGAIN. Returns how many were alerted.
     */
    public function scan(): int
    {
        if (!$this->enabled()) return 0;
        $today = $this->access->day(time());
        $alerted = 0;
        foreach ($this->sharedIps($today) as $shared) {
            $level = $shared['users'] >= self::IP_USERS_AGAIN ? 2 : 1;
            $key = 'risk:link:ip:' . md5($shared['ip_net']) . ':' . date('Ymd');
            if ((int)Cache::get($key, 0) >= $level) continue;
            Cache::put($key, $level, 2 * 86400);
            $user = User::find($shared['alert_user_id']);
            if (!$user) continue;
            $detail = '当天 ' . $shared['users'] . ' 个用户' . ($shared['isolated'] ? "（含已隔离 {$shared['isolated']} 人）" : '') . '：' .
                implode('、', array_map(function ($entry) {
                    return 'uid ' . $entry['user_id'] . ' ' . $entry['label'];
                }, $shared['list']));
            $this->risk->recordFinding($user, 'ip_users', $shared['ip'], $shared['user_agent'], $detail,
                'ip_users|' . $shared['ip_net'] . '|' . date('Ymd'));
            $alerted++;
        }
        return $alerted;
    }

    /**
     * Today's report so far (/report, 📊 今日概况).
     */
    public function reportToday(): array
    {
        // The end is exclusive: what happened this second counts too
        return $this->report($this->access->day(time()), time() + 1);
    }

    /**
     * The daily report's numbers for the day of $from, up to $to (exclusive): today so far, or a whole day.
     * See RiskView::report().
     */
    public function report(int $from, int $to): array
    {
        $day = $this->access->day($from);
        $types = RiskAccessService::TYPES;
        $results = RiskAccessService::RESULTS;
        $base = function () use ($day) { return RiskAccess::where('record_at', $day); };
        $sums = $base()->selectRaw('event_type, result, SUM(occurrences) AS total')->groupBy('event_type', 'result')->get();
        $sum = function (string $type, ?string $result = null) use ($sums, $types, $results) {
            return (int)$sums->filter(function ($row) use ($type, $result, $types, $results) {
                return (int)$row->event_type === $types[$type] && ($result === null || (int)$row->result === $results[$result]);
            })->sum('total');
        };
        $stat = new StatisticalService();
        $stat->setStartAt($from);
        $stat->setEndAt($to);
        $orders = $stat->generateStatData();

        $top = $base()->where('event_type', $types['subscription'])
            ->selectRaw('user_id, SUM(occurrences) AS total, COUNT(DISTINCT ip_net) AS ips, COUNT(DISTINCT ua_hash) AS clients')
            ->groupBy('user_id')->orderByDesc('total')->limit(5)->get();
        $failed = $base()->where('event_type', $types['login'])->where('result', $results['failed'])
            ->selectRaw('user_id, SUM(occurrences) AS total, COUNT(DISTINCT ip_net) AS ips')
            ->groupBy('user_id')->orderByDesc('total')->limit(5)->get();
        $scripts = $base()->where('event_type', $types['subscription'])
            ->where(function ($query) {
                $query->where('user_agent', '')->orWhereRaw('`user_agent` REGEXP ?', [self::SCRIPT_AGENTS]);
            })
            ->selectRaw('user_id, user_agent, SUM(occurrences) AS total')->groupBy('user_id', 'user_agent')
            ->orderByDesc('total')->limit(5)->get();
        $shared = array_slice($this->sharedIps($day), 0, 5);
        $regions = $this->regions($day);
        $ids = $top->pluck('user_id')->merge($failed->pluck('user_id'))->merge($scripts->pluck('user_id'))
            ->merge(array_column($regions, 'user_id'))->unique()->values();
        $emails = User::whereIn('id', $ids)->pluck('email', 'id');
        $email = function ($id) use ($emails) { return $emails[$id] ?? null; };
        $info = $shared ? (new IpInfoService())->lookupMany(array_column($shared, 'ip')) : [];
        $stats = $this->access->stats();

        return [
            'from' => $from,
            'to' => $to,
            'active' => $base()->where('event_type', $types['subscription'])->distinct()->count('user_id'),
            'subscriptions' => $sum('subscription'),
            'logins' => $sum('login', 'ok'),
            'failed_logins' => $sum('login', 'failed'),
            'registrations' => (int)$orders['register_count'],
            'orders' => (int)$orders['order_count'],
            'paid' => (int)$orders['paid_count'],
            'events' => RiskEvent::where('last_seen_at', '>=', $from)->where('last_seen_at', '<', $to)->count(),
            'isolated' => RiskAudit::where('action', 'mark')->where('created_at', '>=', $from)->where('created_at', '<', $to)
                ->distinct()->count('user_id'),
            'limited' => RiskEvent::where('event_type', 'sub_limit')->where('first_seen_at', '>=', $from)->where('first_seen_at', '<', $to)->count(),
            'link_alerts' => RiskEvent::whereIn('event_type', ['ip_users', 'register_link'])
                ->where('first_seen_at', '>=', $from)->where('first_seen_at', '<', $to)->count(),
            'skipped_alerts' => $this->risk->skippedAlerts($from),
            'merged_alerts' => $this->risk->alerts()->dayCounts($from)['merged'],
            'top_subscribers' => $top->map(function ($row) use ($email) {
                return ['user_id' => (int)$row->user_id, 'email' => $email($row->user_id), 'total' => (int)$row->total,
                    'ips' => (int)$row->ips, 'clients' => (int)$row->clients];
            })->all(),
            'shared_ips' => array_map(function ($entry) use ($info) {
                return [
                    'ip_net' => $entry['ip_net'], 'users' => $entry['users'], 'isolated' => $entry['isolated'],
                    'location' => $info[$entry['ip']]['location'] ?? null, 'network' => $info[$entry['ip']]['network'] ?? null,
                ];
            }, $shared),
            'regions' => array_map(function ($entry) use ($email) {
                return $entry + ['email' => $email($entry['user_id'])];
            }, $regions),
            'failed' => $failed->map(function ($row) use ($email) {
                return ['user_id' => (int)$row->user_id, 'email' => $email($row->user_id), 'total' => (int)$row->total, 'ips' => (int)$row->ips];
            })->all(),
            'scripts' => $scripts->map(function ($row) use ($email) {
                return ['user_id' => (int)$row->user_id, 'email' => $email($row->user_id), 'user_agent' => (string)$row->user_agent,
                    'total' => (int)$row->total];
            })->all(),
            'table_rows' => $stats['table_rows'],
            'table_bytes' => $stats['table_bytes'],
            'days' => $stats['days'],
            'errors' => $this->writeErrors($from),
        ];
    }

    /**
     * The day's IPs (an IPv6 /64) with several users subscribing or logged in, left-out IPs aside, the most users
     * first: link_ip_users or more, or two with an isolated one among them. Each with its users (list: up to 5, with
     * what they did), the isolated count and the user to alert about (the latest one not isolated).
     */
    private function sharedIps(int $day): array
    {
        $threshold = max(2, (int)RiskSettings::get('link_ip_users'));
        $types = [RiskAccessService::TYPES['subscription'], RiskAccessService::TYPES['login']];
        $groups = RiskAccess::where('record_at', $day)->whereIn('event_type', $types)
            ->where('result', '!=', RiskAccessService::RESULTS['failed'])->where('ip_net', '!=', '')
            ->selectRaw('ip_net, MAX(ip) AS ip, COUNT(DISTINCT user_id) AS users')->groupBy('ip_net')
            ->havingRaw('COUNT(DISTINCT user_id) >= 2')->orderByDesc('users')->limit(200)->get();
        if (!$groups->count()) return [];
        $exclude = $this->excluder();
        $shared = [];
        foreach ($groups as $group) {
            if ($exclude((string)$group->ip, (string)$group->ip_net)) continue;
            $rows = RiskAccess::where('record_at', $day)->where('ip_net', $group->ip_net)->whereIn('event_type', $types)
                ->where('result', '!=', RiskAccessService::RESULTS['failed'])->orderByDesc('last_seen_at')->get();
            $users = User::whereIn('id', $rows->pluck('user_id')->unique()->values())->get(['id', 'risk_status'])->keyBy('id');
            $isolated = $users->filter(function (User $user) { return (int)$user->risk_status === RiskService::STATUS_RISK; });
            if ($users->count() < ($isolated->count() ? 2 : $threshold)) continue;
            $latest = $rows->first(function (RiskAccess $row) use ($isolated) { return !$isolated->has($row->user_id); }) ?? $rows->first();
            $names = array_flip(RiskAccessService::TYPES);
            $list = $rows->groupBy('user_id')->map(function ($rows, $id) use ($names) {
                $label = $rows->groupBy('event_type')->map(function ($rows, $type) use ($names) {
                    return RiskAccessService::TYPE_NAMES[$names[$type] ?? 'subscription'] . ' ' . (int)$rows->sum('occurrences') . ' 次';
                })->implode('、');
                return ['user_id' => (int)$id, 'label' => $label];
            })->values()->take(5)->all();
            $shared[] = [
                'ip_net' => (string)$group->ip_net, 'ip' => (string)$latest->ip, 'user_agent' => (string)$latest->user_agent,
                'users' => $users->count(), 'isolated' => $isolated->count(), 'alert_user_id' => (int)$latest->user_id,
                'list' => $list,
            ];
        }
        usort($shared, function ($a, $b) { return $b['users'] <=> $a['users']; });
        return $shared;
    }

    /**
     * Users who subscribed from REPORT_REGIONS or more places (country and province, from the IP's location) in the
     * day, left-out IPs aside, with their ASNs too: up to 5, the most places first. The location is only counted here,
     * never matched against.
     */
    private function regions(int $day): array
    {
        $rows = RiskAccess::where('record_at', $day)->where('event_type', RiskAccessService::TYPES['subscription'])
            ->where('ip_net', '!=', '')->get(['user_id', 'ip', 'ip_net']);
        $exclude = $this->excluder();
        $rows = $rows->reject(function (RiskAccess $row) use ($exclude) { return $exclude((string)$row->ip, (string)$row->ip_net); });
        // Only users with several IPs can have several places
        $rows = $rows->groupBy('user_id')->filter(function ($rows) { return $rows->pluck('ip_net')->unique()->count() >= self::REPORT_REGIONS; });
        if (!$rows->count()) return [];
        $info = (new IpInfoService())->lookupMany($rows->flatten(1)->pluck('ip')->unique()->values()->all());
        $regions = [];
        foreach ($rows as $userId => $userRows) {
            $places = $asns = [];
            foreach ($userRows as $row) {
                $location = $info[$row->ip]['location'] ?? null;
                if ($location) $places[implode(' ', array_slice(explode(' ', $location), 0, 2))] = true;
                $asn = $info[$row->ip]['asn_number'] ?? null;
                if ($asn) $asns[$asn] = true;
            }
            if (count($places) >= self::REPORT_REGIONS) {
                $regions[] = ['user_id' => (int)$userId, 'places' => count($places), 'asns' => count($asns)];
            }
        }
        usort($regions, function ($a, $b) { return [$b['places'], $b['asns']] <=> [$a['places'], $a['asns']]; });
        return array_slice($regions, 0, 5);
    }

    /**
     * Whether an IP (and its ip_net) is left out of the checks: private or reserved, in the IP allowlist, or a node's.
     */
    private function excluder(): callable
    {
        $allow = RiskIndicator::where('type', 'allow_ip')->where('enabled', 1)->pluck('value')->all();
        $nodes = $this->access->nodeNets();
        return function (string $ip, string $net) use ($allow, $nodes): bool {
            if (!$this->access->isPublic($ip) || isset($nodes[$net])) return true;
            foreach ($allow as $entry) {
                if ($this->risk->ipMatches($ip, (string)$entry) || $this->risk->ipRangeWithin($net, (string)$entry)) return true;
            }
            return false;
        };
    }

    private function writeErrors(int $time): int
    {
        try {
            return (int)Cache::get('risk:access:errors:' . date('Ymd', $time), 0);
        } catch (\Throwable $e) {
            return 0;
        }
    }

    private function uids(array $ids): string
    {
        $ids = array_values(array_unique(array_map('intval', $ids)));
        return 'uid ' . implode('、', array_slice($ids, 0, 5)) . (count($ids) > 5 ? ' 等 ' . count($ids) . ' 个' : '');
    }
}
