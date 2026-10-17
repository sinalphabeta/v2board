<?php

namespace App\Http\Controllers\V1\Admin;

use App\Exceptions\RiskIpAllowlistedException;
use App\Http\Controllers\Controller;
use App\Models\Plan;
use App\Models\RiskAccess;
use App\Models\RiskAudit;
use App\Models\RiskConn;
use App\Models\RiskEvent;
use App\Models\RiskIndicator;
use App\Models\ServerGroup;
use App\Models\User;
use App\Plugins\RiskTelegram\RiskOperator;
use App\Services\IpInfoService;
use App\Services\RiskAccessService;
use App\Services\RiskConnService;
use App\Services\RiskService;
use App\Services\RiskSettings;
use Illuminate\Http\Request;

/**
 * The admin panel's risk-control pages: indicators, isolated users, events and the audit log.
 * Like the other admin endpoints: GET reads, POST writes, lists return {data, total} for current / pageSize,
 * errors are abort(500, '…'). Changes go through RiskService and are audited as the admin.
 */
class RiskController extends Controller
{
    // delete: disabled (the switch, the risk bot's /del…); drop: deleted here
    private const ACTIONS = ['add', 'edit', 'delete', 'drop', 'mark', 'unmark', 'setting', 'reset', 'exempt'];

    public function overview()
    {
        $settings = RiskSettings::fresh();
        $honeypot = $settings['honeypot_group_id'];
        $group = $honeypot > 0 ? ServerGroup::find($honeypot) : null;
        $counts = RiskIndicator::where('enabled', 1)->selectRaw('type, COUNT(*) AS total')->groupBy('type')->pluck('total', 'type');
        $asnAvailable = (new IpInfoService())->asnDatabaseAvailable();
        $warnings = [];
        if ($honeypot <= 0) $warnings[] = '没有设置蜜罐权限组：被隔离的用户拿不到任何节点';
        elseif (!$group) $warnings[] = "蜜罐权限组 #{$honeypot} 不存在：被隔离的用户拿不到任何节点";
        if (!$settings['bot_token']) $warnings[] = '没有设置风险 Bot Token：不会发告警，风险 Bot 也收不到命令';
        elseif (!$settings['alert_chat_id']) $warnings[] = '没有设置告警群 Chat ID：不会发告警';
        $mixed = (new RiskService())->mixedHoneypotNodes();
        if ($mixed) $warnings[] = '这些节点同时属于蜜罐组和普通组：' . implode('、', $mixed);
        if (($counts['asn'] ?? 0) && !$asnAvailable) $warnings[] = '有 ASN 名单，但 ASN 数据库不可用';
        $indicators = [];
        foreach (array_keys(RiskService::TYPES) as $type) $indicators[$type] = (int)($counts[$type] ?? 0);
        return response(['data' => [
            'isolated_users' => User::where('risk_status', RiskService::STATUS_RISK)->count(),
            'indicators' => $indicators,
            'events_24h' => RiskEvent::where('last_seen_at', '>=', time() - 86400)->count(),
            'events_7d' => RiskEvent::where('last_seen_at', '>=', time() - 7 * 86400)->count(),
            'honeypot_group' => $honeypot > 0 ? ['id' => $honeypot, 'name' => $group ? $group->name : null] : null,
            'asn_database_available' => $asnAvailable,
            'warnings' => $warnings,
        ]]);
    }

    /**
     * The settings in effect, in full (only admins can read them), and whether each was saved here or comes from .env.
     */
    public function settingFetch()
    {
        return response(['data' => RiskSettings::fresh() + ['sources' => RiskSettings::sources()]]);
    }

    /**
     * Save the settings sent; each changed one is audited (the token and chat ID without their values).
     */
    public function settingSave(Request $request)
    {
        $values = [];
        if ($request->has('bot_token')) {
            $token = trim((string)$request->input('bot_token'));
            if ($token !== '' && !preg_match('/^\d+:[A-Za-z0-9_-]{20,}$/', $token)) abort(500, 'Bot Token 格式有误，应该像 123456789:AAxxxxxxxx');
            $values['bot_token'] = $token;
        }
        if ($request->has('alert_chat_id')) {
            $chatId = trim((string)$request->input('alert_chat_id'));
            if ($chatId !== '' && !preg_match('/^-?\d+$/', $chatId)) abort(500, '告警群 Chat ID 应该是数字：在群里给风险 Bot 发 /id 可以查看');
            $values['alert_chat_id'] = $chatId;
        }
        if ($request->has('bot_operators')) {
            $operators = [];
            foreach (preg_split('/[\r\n,，]+/u', (string)$request->input('bot_operators')) as $entry) {
                $entry = trim($entry);
                if ($entry === '') continue;
                if (!preg_match('/^([1-9]\d{3,15})(?:\s+(\S.{0,19}))?$/u', $entry, $match)) {
                    abort(500, '可操作的 Telegram ID 每行一个：先写数字 ID（在风险 Bot 里发 /id 可以查看），后面可以空一格写备注，最多 20 个字');
                }
                $operators[$match[1]] = $match[1] . (isset($match[2]) ? ' ' . trim($match[2]) : '');
            }
            if (count($operators) > 20) abort(500, '可操作的 Telegram ID 最多 20 个');
            $values['bot_operators'] = implode("\n", $operators);
        }
        if ($request->has('honeypot_group_id')) {
            $groupId = trim((string)$request->input('honeypot_group_id'));
            if (!ctype_digit($groupId)) abort(500, '蜜罐权限组有误');
            if ((int)$groupId > 0 && !ServerGroup::find((int)$groupId)) abort(500, '蜜罐权限组不存在');
            $values['honeypot_group_id'] = (int)$groupId;
        }
        if ($request->has('ip_info_enabled')) {
            $enabled = (string)$request->input('ip_info_enabled');
            if (!in_array($enabled, ['0', '1'], true)) abort(500, '参数错误');
            $values['ip_info_enabled'] = $enabled === '1';
        }
        if ($request->has('asn_cache_ttl')) {
            $ttl = trim((string)$request->input('asn_cache_ttl'));
            if (!ctype_digit($ttl) || (int)$ttl > 604800) abort(500, 'ASN 缓存时间应该是 0 到 604800 之间的秒数');
            $values['asn_cache_ttl'] = (int)$ttl;
        }
        if ($request->has('trusted_proxies')) {
            $service = new RiskService();
            $proxies = $invalid = [];
            foreach (preg_split('/[\s,，]+/u', (string)$request->input('trusted_proxies'), -1, PREG_SPLIT_NO_EMPTY) as $proxy) {
                $value = $service->normalizeIndicatorValue('ip', $proxy);
                if ($value === null) $invalid[] = $proxy;
                else $proxies[] = $value;
            }
            if ($invalid) abort(500, '可信代理里这些不是 IP 或 CIDR：' . implode('、', $invalid));
            $values['trusted_proxies'] = implode(',', array_unique($proxies));
        }
        foreach (['access_log_enabled', 'link_detection', 'daily_report', 'conn_log_enabled'] as $name) {
            if (!$request->has($name)) continue;
            $enabled = (string)$request->input($name);
            // An admin panel older than a switch sends the value it fetched, form-encoded: true / false
            if (!in_array($enabled, ['0', '1', 'true', 'false'], true)) abort(500, '参数错误');
            $values[$name] = $enabled === '1' || $enabled === 'true';
        }
        $ranges = [
            'access_log_days' => [7, 365, '访问记录保留天数应该是 7 到 365 之间的整数'],
            'sub_daily_limit' => [0, 100000, '每天订阅上限应该是 0 到 100000 之间的整数，0 表示不限'],
            'link_ip_users' => [2, 50, '同 IP 多用户阈值应该是 2 到 50 之间的整数'],
            'alert_daily_limit' => [5, 500, '每类告警每天上限应该是 5 到 500 之间的整数'],
            'sub_burst_limit' => [0, 500, '10 分钟订阅次数告警应该是 0（不检测）或 5 到 500 之间的整数'],
            'conn_log_days' => [7, 365, '连接记录保留天数应该是 7 到 365 之间的整数'],
            'conn_ip_limit' => [0, 200, '1 小时连接 IP 数告警应该是 0（不检测）或 5 到 200 之间的整数'],
            'conn_link_ips' => [0, 20, '命中测活 IP 告警应该是 0（不检测）或 1 到 20 之间的整数'],
        ];
        foreach ($ranges as $name => [$min, $max, $error]) {
            if (!$request->has($name)) continue;
            $value = trim((string)$request->input($name));
            if (!ctype_digit($value) || (int)$value < $min || (int)$value > $max) abort(500, $error);
            // A handful of updates in 10 minutes is normal (a client started, a few devices), and a few IPs in an hour
            // (home, office, a phone moving)
            if (in_array($name, ['sub_burst_limit', 'conn_ip_limit'], true) && (int)$value > 0 && (int)$value < 5) abort(500, $error);
            $values[$name] = (int)$value;
        }
        $service = $this->riskService($request);
        foreach (RiskSettings::save($values) as $name => [$old, $new]) $service->auditSetting($name, $old, $new);
        return response(['data' => true]);
    }

    /**
     * IP indicators and the allowlists also say where their IPs are (a CIDR by its network address), see ipInfoFields().
     * A node IP given as a domain name has `host`: the IPs it resolves to (the latest first), when it was last resolved
     * and when a lookup last failed; where it is is where its latest IP is.
     */
    public function indicatorFetch(Request $request)
    {
        $query = RiskIndicator::query();
        $type = $request->input('type');
        if ($type !== null) {
            if (!$this->validType($type)) abort(500, '名单类型有误');
            $query->where('type', $type);
        }
        $enabled = $request->input('enabled');
        if ($enabled !== null) $query->where('enabled', $enabled ? 1 : 0);
        $keyword = $this->keyword($request);
        if ($keyword !== null) {
            $query->where(function ($query) use ($keyword) {
                $query->where('value', 'like', $keyword)->orWhere('note', 'like', $keyword);
            });
        }
        return $this->paged($request, $query->orderByDesc('id'), function ($indicators) {
            $known = (new RiskAccessService())->nodeHosts();
            $hosts = [];
            foreach ($indicators as $indicator) {
                if ($indicator->type !== 'node_ip' || !RiskAccessService::isHost((string)$indicator->value)) continue;
                $host = $known[$indicator->value] ?? [];
                $ips = $host['ips'] ?? [];
                arsort($ips);
                $hosts[$indicator->id] = [
                    'ips' => array_map('strval', array_keys($ips)),
                    'resolved_at' => $host['resolved_at'] ?? null,
                    'failed_at' => $host['failed_at'] ?? null,
                ];
            }
            $ips = $indicators->filter(function (RiskIndicator $indicator) {
                return $indicator->type === 'ip' || in_array($indicator->type, RiskService::ALLOW_TYPES, true);
            })->mapWithKeys(function (RiskIndicator $indicator) use ($hosts) {
                if (isset($hosts[$indicator->id])) return [$indicator->id => $hosts[$indicator->id]['ips'][0] ?? null];
                return [$indicator->id => explode('/', (string)$indicator->value)[0]];
            })->filter();
            $info = $ips->isEmpty() ? [] : (new IpInfoService())->lookupMany($ips->values()->all());
            return $indicators->map(function (RiskIndicator $indicator) use ($ips, $info, $hosts) {
                $row = $indicator->toArray();
                if (isset($hosts[$indicator->id])) $row['host'] = $hosts[$indicator->id];
                if ($indicator->type !== 'ip' && !in_array($indicator->type, RiskService::ALLOW_TYPES, true)) return $row;
                return $row + $this->ipInfoFields(isset($ips[$indicator->id]) ? ($info[$ips[$indicator->id]] ?? null) : null);
            })->values();
        });
    }

    /**
     * With an id: change the indicator's value and note. Without: add indicators of a type, one or more per line.
     * Both return the IP indicators that allowlist entries disabled (`disabled`); adding also groups the values,
     * see RiskService::addIndicators().
     */
    public function indicatorSave(Request $request)
    {
        $service = $this->riskService($request);
        $note = $this->note($request->input('note'));
        if ($request->input('id')) {
            $indicator = RiskIndicator::find((int)$request->input('id'));
            if (!$indicator) abort(500, '名单不存在');
            $value = $service->normalizeIndicatorValue($indicator->type, $request->input('value', $indicator->value));
            if ($value === null) abort(500, RiskService::formatHint($indicator->type) ?? '值的格式有误');
            if (RiskIndicator::where('type', $indicator->type)->where('value', $value)->where('id', '!=', $indicator->id)->exists()) {
                abort(500, '名单里已经有这个值');
            }
            try {
                $service->updateIndicator($indicator, ['value' => $value, 'note' => $note], $disabled);
            } catch (RiskIpAllowlistedException $e) {
                abort(500, "{$e->value} 在" . RiskService::entryPhrase($e->entry) . ' 里，不能加入 IP 名单');
            }
            return response(['data' => ['disabled' => $disabled]]);
        }

        $type = $request->input('type');
        if (!$this->validType($type)) abort(500, '名单类型有误');
        // A UA keyword may contain spaces and commas, so UAs go one per line; other values may also be separated by them
        $lines = preg_split('/\R/u', (string)$request->input('values', ''));
        if ($type !== 'ua') $lines = preg_split('/[\s,，]+/u', implode("\n", $lines));
        $values = array_values(array_unique(array_filter(array_map('trim', $lines), 'strlen')));
        if (!$values) abort(500, '请输入要添加的值');
        return response(['data' => $service->addIndicators($type, $values, $note)]);
    }

    /**
     * Enable or disable an indicator (disabling an email indicator releases its users). Returns the IP indicators
     * that an enabled allowlist entry disabled (`disabled`).
     */
    public function indicatorUpdate(Request $request)
    {
        $indicator = RiskIndicator::find((int)$request->input('id'));
        if (!$indicator) abort(500, '名单不存在');
        $enabled = (string)$request->input('enabled');
        if (!in_array($enabled, ['0', '1'], true)) abort(500, '参数错误');
        $service = $this->riskService($request);
        $disabled = [];
        if ($enabled === '1') {
            try {
                $service->updateIndicator($indicator, ['enabled' => 1], $disabled);
            } catch (RiskIpAllowlistedException $e) {
                abort(500, "{$e->value} 在" . RiskService::entryPhrase($e->entry) . ' 里，不能启用');
            }
        } else {
            $service->removeIndicator($indicator);
        }
        return response(['data' => ['disabled' => $disabled]]);
    }

    /**
     * Delete an indicator for good, enabled or not (the switch only disables it): deleting an enabled email indicator
     * releases its users, and the IP indicators an allowlist entry disabled stay disabled.
     */
    public function indicatorDrop(Request $request)
    {
        $indicator = RiskIndicator::find((int)$request->input('id'));
        if (!$indicator) abort(500, '名单不存在');
        if (!$this->riskService($request)->deleteIndicator($indicator)) abort(500, '删除失败');
        return response(['data' => true]);
    }

    public function userFetch(Request $request)
    {
        $query = User::where('risk_status', RiskService::STATUS_RISK);
        $keyword = $this->keyword($request);
        if ($keyword !== null) $query->where('email', 'like', $keyword);
        return $this->paged($request, $query->orderByDesc('risk_marked_at')->orderByDesc('id'), function ($users) {
            $plans = Plan::whereIn('id', $users->pluck('plan_id')->filter()->unique()->values())->pluck('name', 'id');
            $indicators = RiskIndicator::whereIn('id', $users->pluck('risk_indicator_id')->filter()->unique()->values())->pluck('value', 'id');
            $lastSeen = RiskEvent::whereIn('user_id', $users->pluck('id'))
                ->selectRaw('user_id, MAX(last_seen_at) AS last_seen_at')->groupBy('user_id')->pluck('last_seen_at', 'user_id');
            return $users->map(function (User $user) use ($plans, $indicators, $lastSeen) {
                return [
                    'id' => $user->id,
                    'email' => $user->email,
                    'plan_id' => $user->plan_id,
                    'plan_name' => $plans[$user->plan_id] ?? null,
                    'expired_at' => $user->expired_at,
                    'banned' => (int)$user->banned,
                    'risk_marked_at' => $user->risk_marked_at,
                    'risk_indicator' => $indicators[$user->risk_indicator_id] ?? null,
                    'last_seen_at' => isset($lastSeen[$user->id]) ? (int)$lastSeen[$user->id] : null,
                ];
            })->values();
        });
    }

    /**
     * Isolate a user: add their email to the email indicators.
     */
    public function userIsolate(Request $request)
    {
        $user = $this->user($request);
        try {
            $this->riskService($request)->isolateUser($user, $this->note($request->input('note')));
        } catch (\InvalidArgumentException $e) {
            abort(500, '这个用户的邮箱格式无效，无法加入名单');
        }
        return response(['data' => true]);
    }

    /**
     * Release a user: disable the email indicators that match their email.
     */
    public function userRelease(Request $request)
    {
        $this->riskService($request)->releaseUser($this->user($request));
        return response(['data' => true]);
    }

    public function eventFetch(Request $request)
    {
        $query = RiskEvent::query();
        if ($request->input('user_id')) $query->where('user_id', (int)$request->input('user_id'));
        if (is_string($request->input('event_type'))) $query->where('event_type', $request->input('event_type'));
        if (is_string($request->input('ip'))) $query->where('ip', $request->input('ip'));
        $keyword = $this->keyword($request);
        if ($keyword !== null) $query->whereIn('user_id', User::where('email', 'like', $keyword)->select('id'));
        return $this->paged($request, $query->orderByDesc('last_seen_at')->orderByDesc('id'), function ($events) {
            $users = User::whereIn('id', $events->pluck('user_id')->filter()->unique()->values())
                ->get(['id', 'email', 'risk_status'])->keyBy('id');
            $ruleIds = $events->flatMap(function (RiskEvent $event) { return $this->ruleIds($event); })->unique()->values();
            $rules = RiskIndicator::whereIn('id', $ruleIds)->get(['id', 'type', 'value'])->keyBy('id');
            // Deleted indicators, as their deletion recorded them
            $dropped = RiskAudit::where('action', 'drop')->whereIn('indicator_id', $ruleIds->diff($rules->keys())->values())
                ->get(['indicator_id', 'type', 'value'])->keyBy('indicator_id');
            $service = new RiskService();
            $allowlist = RiskIndicator::whereIn('type', RiskService::ALLOW_TYPES)->where('enabled', 1)->get();
            $ipRules = RiskIndicator::where('type', 'ip')->where('enabled', 1)->orderBy('id')->pluck('value');
            $uaRules = RiskIndicator::where('type', 'ua')->where('enabled', 1)->pluck('value');
            $isNode = $service->access()->nodeMatcher();
            $userCounts = $service->recentUserCounts($events->pluck('ip')->all());
            $info = (new IpInfoService())->lookupMany($events->pluck('ip')->all());
            return $events->map(function (RiskEvent $event) use ($users, $rules, $dropped, $service, $allowlist, $ipRules, $uaRules, $isNode, $userCounts, $info) {
                $user = $users->get($event->user_id);
                return [
                    'id' => $event->id,
                    'user_id' => $event->user_id,
                    'email' => $user ? $user->email : null,
                    'user_isolated' => $user ? (int)$user->risk_status === RiskService::STATUS_RISK : false,
                    'event_type' => $event->event_type,
                    'ip' => $event->ip,
                    // Whether an enabled allowlist entry (IP 白名单 or 节点 IP) covers the IP now (the event may be from before)
                    'ip_allowed' => $allowlist->contains(function (RiskIndicator $entry) use ($service, $event) {
                        return $service->entryMatches((string)$event->ip, $entry);
                    }),
                    // A node's exit IP: in the node IP list, or one the node APIs were called from lately (not ip_allowed
                    // then, until it is added to the list)
                    'ip_node' => filter_var($event->ip, FILTER_VALIDATE_IP) ? $isNode((string)$event->ip) : false,
                    // The enabled IP indicator covering the IP now (the same IP or a range): it is listed already
                    'ip_listed' => $ipRules->first(function ($rule) use ($service, $event) {
                        return $service->ipMatches((string)$event->ip, trim((string)$rule));
                    }),
                    // What 放行此 IP adds to the allowlist (an IPv6 address as its /64), null for a private or reserved IP
                    'ip_allow_value' => $service->allowRangeFor((string)$event->ip),
                    // Users of the IP in the last 30 days of risk events: many suggest a CDN or proxy address
                    'ip_users_30d' => $userCounts[$event->ip] ?? 0,
                    'user_agent' => $event->user_agent,
                    // Whether a UA indicator matches the user agent now (it contains the keyword, in any case)
                    'ua_listed' => (string)$event->user_agent !== '' && $uaRules->contains(function ($rule) use ($event) {
                        $rule = trim((string)$rule);
                        return $rule !== '' && stripos((string)$event->user_agent, $rule) !== false;
                    }),
                    'occurrences' => (int)$event->occurrences,
                    'first_seen_at' => $event->first_seen_at,
                    'last_seen_at' => $event->last_seen_at,
                    'rules' => array_map(function ($id) use ($rules, $dropped) {
                        $rule = $rules->get($id) ?? $dropped->get($id);
                        if (!$rule) return "#{$id}";
                        return "{$rule->type}:{$rule->value}" . ($rules->has($id) ? '' : '（已删除）');
                    }, $this->ruleIds($event)),
                    // What a check found, for the event types in RiskService::FINDING_TYPES
                    'detail' => $event->detail,
                ] + $this->ipInfoFields($info[$event->ip] ?? null);
            })->values();
        });
    }

    /**
     * The access log, the latest first. It takes a date range (date_from / date_to as Y-m-d, both default today):
     * at most 31 days, or up to the access log's days with a user (user_id, keyword) or an IP (an IPv6 address matches
     * its /64). Pages of at most 100 rows: the query runs on webman, alongside the subscriptions.
     */
    public function accessFetch(Request $request)
    {
        $access = new RiskAccessService();
        $today = $access->day(time());
        $from = $this->date($request->input('date_from')) ?? $today;
        $to = $this->date($request->input('date_to')) ?? $today;
        if ($from > $to) [$from, $to] = [$to, $from];
        $query = RiskAccess::where('record_at', '>=', $from)->where('record_at', '<=', $to);
        $narrowed = false;
        if ($request->input('user_id')) {
            $query->where('user_id', (int)$request->input('user_id'));
            $narrowed = true;
        }
        $keyword = $this->keyword($request);
        if ($keyword !== null) {
            $query->whereIn('user_id', User::where('email', 'like', $keyword)->select('id'));
            $narrowed = true;
        }
        $ip = trim((string)$request->input('ip', ''));
        if ($ip !== '') {
            if (!filter_var($ip, FILTER_VALIDATE_IP)) abort(500, 'IP 格式有误');
            $query->where('ip_net', $access->ipNet($ip));
            $narrowed = true;
        }
        $maxDays = $narrowed ? max(31, (int)RiskSettings::get('access_log_days')) : 31;
        if (($to - $from) / 86400 + 1 > $maxDays) {
            abort(500, $narrowed ? "日期范围最多 {$maxDays} 天" : '没有选用户或 IP 时，日期范围最多 31 天');
        }
        foreach (['event_type' => RiskAccessService::TYPES, 'result' => RiskAccessService::RESULTS] as $field => $codes) {
            $value = $request->input($field);
            if ($value === null || $value === '') continue;
            if (!is_string($value) || !isset($codes[$value])) abort(500, $field === 'result' ? '结果有误' : '类型有误');
            $query->where($field, $codes[$value]);
        }
        $query->orderByDesc('record_at')->orderByDesc('last_seen_at');
        return $this->paged($request, $query, function ($rows) use ($access) {
            $users = User::whereIn('id', $rows->pluck('user_id')->unique()->values())->get(['id', 'email', 'risk_status'])->keyBy('id');
            $info = (new IpInfoService())->lookupMany($rows->pluck('ip')->unique()->values()->all());
            $isNode = $access->nodeMatcher();
            $types = array_flip(RiskAccessService::TYPES);
            $results = array_flip(RiskAccessService::RESULTS);
            return $rows->map(function (RiskAccess $row) use ($users, $info, $isNode, $types, $results) {
                $user = $users->get($row->user_id);
                return [
                    // The primary key, for the table's row key
                    'key' => implode('|', [$row->record_at, $row->user_id, $row->event_type, $row->result, $row->ip_net, $row->ua_hash]),
                    'record_at' => $row->record_at,
                    'user_id' => $row->user_id,
                    'email' => $user ? $user->email : null,
                    'user_isolated' => $user ? (int)$user->risk_status === RiskService::STATUS_RISK : false,
                    'event_type' => $types[$row->event_type] ?? null,
                    'result' => $results[$row->result] ?? null,
                    'ip' => $row->ip,
                    'ip_net' => $row->ip_net,
                    // A node's exit IP (the node IP list, or seen calling the node APIs): the user came through a node
                    'ip_node' => $row->ip_net !== '' && $isNode((string)$row->ip, (string)$row->ip_net),
                    // The row that takes a user's new IP and user agent combinations after many subscriptions in a day
                    'overflow' => $row->ip_net === '',
                    'user_agent' => $row->user_agent,
                    'occurrences' => $row->occurrences,
                    'first_seen_at' => $row->first_seen_at,
                    'last_seen_at' => $row->last_seen_at,
                ] + $this->ipInfoFields($info[$row->ip] ?? null);
            })->values();
        }, 100);
    }

    /**
     * The users and sources online (reported in the last 3 minutes, or with window=3600 the last hour) by province,
     * the connection log's state, and the panel's 节点用户设备数统计最低阈值: above 0, the nodes leave out the users
     * with less traffic in a report, as a probe has.
     */
    public function connLive(Request $request)
    {
        $window = (int)$request->input('window') === 3600 ? 3600 : RiskConnService::ONLINE_SECONDS;
        $conn = new RiskConnService();
        return response(['data' => $conn->live($window) + [
            'stats' => $conn->stats(),
            'device_min_traffic' => (int)config('v2board.server_device_online_min_traffic', 0),
        ]]);
    }

    /**
     * The connection log by user, the most sources first: each user's sources in a date range (see connRange()), with
     * how spread they are (RiskConnService::summarize()), the nodes and how many are probing IPs (probe_hits, null
     * for the users isolated now: theirs are the probing IPs). The other filters (a user, an IP, see connFilter())
     * pick the users, whose sources all count.
     */
    public function connUsers(Request $request)
    {
        $conn = new RiskConnService();
        $picked = RiskConn::query();
        [$from, $to, $narrowed] = $this->connRange($request, $picked);
        $filtered = $this->connFilter($request, $picked, $conn);
        $query = RiskConn::where('record_at', '>=', $from)->where('record_at', '<=', $to)->where('ip_net', '!=', '');
        if ($narrowed || $filtered) $query->whereIn('user_id', $picked->where('ip_net', '!=', '')->select('user_id'));
        $total = (clone $query)->distinct()->count('user_id');
        $current = max(1, (int)$request->input('current', 1));
        $pageSize = min(100, max(10, (int)$request->input('pageSize', 10)));
        $page = (clone $query)->selectRaw('user_id, COUNT(DISTINCT ip_net) AS sources, SUM(reports) AS reports, MAX(last_seen_at) AS last_seen_at')
            ->groupBy('user_id')->orderByDesc('sources')->orderByDesc('last_seen_at')->forPage($current, $pageSize)->get();
        $ids = $page->pluck('user_id')->all();
        $rows = RiskConn::where('record_at', '>=', $from)->where('record_at', '<=', $to)->whereIn('user_id', $ids)
            ->get(['user_id', 'ip_net', 'ip', 'servers', 'first_seen_at', 'last_seen_at'])->groupBy('user_id');
        $info = (new IpInfoService())->lookupMany($rows->flatten(1)->pluck('ip')->unique()->values()->all());
        $users = User::whereIn('id', $ids)->get(['id', 'email', 'risk_status'])->keyBy('id');
        $summaries = [];
        foreach ($rows as $userId => $userRows) $summaries[$userId] = $conn->summarize($userRows, $info);
        $servers = $conn->servers(array_merge([], ...array_column($summaries, 'nodes')));
        $probes = $conn->probeUsers($rows->flatten(1)->pluck('ip_net')->filter()->unique()->values()->all());
        return response(['data' => $page->map(function ($row) use ($users, $summaries, $servers, $rows, $probes) {
            $user = $users->get($row->user_id);
            $isolated = $user ? (int)$user->risk_status === RiskService::STATUS_RISK : false;
            $summary = $summaries[$row->user_id] ?? [];
            $nets = $rows->get($row->user_id, collect())->pluck('ip_net')->unique();
            return [
                'user_id' => (int)$row->user_id,
                'email' => $user ? $user->email : null,
                'user_isolated' => $isolated,
                'reports' => (int)$row->reports,
                'servers' => array_values(array_intersect_key($servers, array_flip($summary['nodes'] ?? []))),
                'probe_hits' => $isolated ? null : $nets->filter(function ($net) use ($probes) { return isset($probes[$net]); })->count(),
            ] + array_diff_key($summary, ['nodes' => 1]);
        })->values(), 'total' => $total]);
    }

    /**
     * The connection log, the latest first, like accessFetch(): a date range (see connRange()) and the other filters
     * (see connFilter()). Each row says whether a list covers its source now, whether it is shared, and which users
     * isolated now connected from it too (a probing IP). Pages of at most 100 rows.
     */
    public function connFetch(Request $request)
    {
        $conn = new RiskConnService();
        $query = RiskConn::query();
        $this->connRange($request, $query);
        $this->connFilter($request, $query, $conn);
        $query->orderByDesc('record_at')->orderByDesc('last_seen_at');
        return $this->paged($request, $query, function ($rows) use ($conn) {
            $users = User::whereIn('id', $rows->pluck('user_id')->unique()->values())->get(['id', 'email', 'risk_status'])->keyBy('id');
            $info = (new IpInfoService())->lookupMany($rows->pluck('ip')->unique()->values()->all());
            $isNode = (new RiskAccessService())->nodeMatcher();
            $servers = $conn->servers($rows->flatMap(function (RiskConn $row) { return array_filter(explode(',', (string)$row->servers)); })->all());
            $nets = $rows->pluck('ip_net')->filter()->unique()->values()->all();
            $shared = $conn->sharedNets($nets);
            $probes = $conn->probeUsers($nets);
            $emails = User::whereIn('id', array_merge([], ...array_map('array_keys', array_values($probes))))->pluck('email', 'id');
            $service = new RiskService();
            $allowlist = RiskIndicator::whereIn('type', RiskService::ALLOW_TYPES)->where('enabled', 1)->get();
            $ipRules = RiskIndicator::where('type', 'ip')->where('enabled', 1)->orderBy('id')->pluck('value');
            return $rows->map(function (RiskConn $row) use ($users, $info, $isNode, $servers, $shared, $probes, $emails, $service, $allowlist, $ipRules) {
                $user = $users->get($row->user_id);
                $source = $row->ip_net !== '';
                $owners = array_diff(array_keys($probes[$row->ip_net] ?? []), [(int)$row->user_id]);
                return [
                    // The primary key, for the table's row key
                    'key' => implode('|', [$row->record_at, $row->user_id, $row->ip_net]),
                    'record_at' => $row->record_at,
                    'user_id' => $row->user_id,
                    'email' => $user ? $user->email : null,
                    'user_isolated' => $user ? (int)$user->risk_status === RiskService::STATUS_RISK : false,
                    'ip' => $row->ip,
                    'ip_net' => $row->ip_net,
                    // A node IP (a relay's address): only kept for isolated users
                    'ip_node' => $source && $isNode((string)$row->ip, (string)$row->ip_net),
                    // Whether an enabled allowlist entry (IP 白名单 or 节点 IP) covers the source now
                    'ip_allowed' => $source && $allowlist->contains(function (RiskIndicator $entry) use ($service, $row) {
                        return $service->entryMatches((string)$row->ip, $entry);
                    }),
                    // The enabled IP indicator covering the whole source now (the same IP or a range): it is listed already
                    'ip_listed' => $source ? $ipRules->first(function ($rule) use ($service, $row) {
                        return $service->ipRangeWithin((string)$row->ip_net, trim((string)$rule));
                    }) : null,
                    // The users not isolated who connected from it in the last 7 days, when that many share it (a relay
                    // not in the node IPs yet, a carrier's NAT): the checks leave it out; else 0
                    'shared' => (int)($shared[$row->ip_net] ?? 0),
                    // The other users isolated now who connected from it: a probing IP
                    'probe_users' => array_map(function ($id) use ($emails) { return ['id' => $id, 'email' => $emails[$id] ?? null]; }, array_values($owners)),
                    // The row that takes a user's sources over the daily limit
                    'overflow' => !$source,
                    'servers' => array_values(array_intersect_key($servers, array_flip(array_filter(explode(',', (string)$row->servers))))),
                    'reports' => $row->reports,
                    'first_seen_at' => $row->first_seen_at,
                    'last_seen_at' => $row->last_seen_at,
                ] + $this->ipInfoFields($info[$row->ip] ?? null);
            })->values();
        }, 100);
    }

    /**
     * The probing IPs (RiskConnService::probes()), the latest first, with the isolated users' emails, the nodes'
     * names and where they are; ip: that source only. Pages of at most 100.
     */
    public function connProbes(Request $request)
    {
        $conn = new RiskConnService();
        $ip = trim((string)$request->input('ip', ''));
        if ($ip !== '' && !filter_var($ip, FILTER_VALIDATE_IP)) abort(500, 'IP 格式有误');
        $current = max(1, (int)$request->input('current', 1));
        $pageSize = min(100, max(10, (int)$request->input('pageSize', 10)));
        [$rows, $total] = $conn->probes($current, $pageSize, $ip === '' ? null : $ip);
        $emails = User::whereIn('id', array_merge([], ...array_column($rows, 'users')))->pluck('email', 'id');
        $servers = $conn->servers(array_merge([], ...array_column($rows, 'nodes')));
        $info = $rows ? (new IpInfoService())->lookupMany(array_column($rows, 'ip')) : [];
        return response(['data' => array_map(function (array $row) use ($emails, $servers, $info) {
            return array_merge($row, [
                'users' => array_map(function ($id) use ($emails) { return ['id' => $id, 'email' => $emails[$id] ?? null]; }, $row['users']),
                'servers' => array_values(array_intersect_key($servers, array_flip($row['nodes']))),
            ], $this->ipInfoFields($info[$row['ip']] ?? null));
        }, $rows), 'total' => $total]);
    }

    /**
     * Delete a probing IP (ip_net: an IP, or an IPv6 /64): its rows of the users isolated now. Audited as drop.
     */
    public function connProbeDrop(Request $request)
    {
        $net = trim((string)$request->input('ip_net', ''));
        $address = explode('/', $net)[0];
        if (!filter_var($address, FILTER_VALIDATE_IP) || $net !== (new RiskAccessService())->ipNet($address)) abort(500, 'IP 格式有误');
        $users = (new RiskConnService())->dropProbe($net);
        if ($users === null) abort(500, '这不是测活 IP');
        $this->riskService($request)->auditProbeDrop($net, $users);
        return response(['data' => true]);
    }

    /**
     * Narrow a connection log query by date (date_from / date_to as Y-m-d, both default today), user (user_id,
     * keyword) and IP (an IPv6 address matches its /64): at most 31 days, or a year with a user or an IP (an isolated
     * user's rows are kept for good). Returns [from, to, narrowed]: the days' 0:00, and whether a user or an IP was given.
     */
    private function connRange(Request $request, $query): array
    {
        $access = new RiskAccessService();
        $today = $access->day(time());
        $from = $this->date($request->input('date_from')) ?? $today;
        $to = $this->date($request->input('date_to')) ?? $today;
        if ($from > $to) [$from, $to] = [$to, $from];
        $query->where('record_at', '>=', $from)->where('record_at', '<=', $to);
        $narrowed = false;
        if ($request->input('user_id')) {
            $query->where('user_id', (int)$request->input('user_id'));
            $narrowed = true;
        }
        $keyword = $this->keyword($request);
        if ($keyword !== null) {
            $query->whereIn('user_id', User::where('email', 'like', $keyword)->select('id'));
            $narrowed = true;
        }
        $ip = trim((string)$request->input('ip', ''));
        if ($ip !== '') {
            if (!filter_var($ip, FILTER_VALIDATE_IP)) abort(500, 'IP 格式有误');
            $query->where('ip_net', $access->ipNet($ip));
            $narrowed = true;
        }
        $maxDays = $narrowed ? 366 : 31;
        if (($to - $from) / 86400 + 1 > $maxDays) abort(500, $narrowed ? "日期范围最多 {$maxDays} 天" : '没有选用户或 IP 时，日期范围最多 31 天');
        return [$from, $to, $narrowed];
    }

    /**
     * The connection log's other filters: a node (server, as v2node3), online (reported in the last 3 minutes, or
     * the last hour with online=3600) and a place (place: a province, 海外 or 未知, see RiskConnService::placeName();
     * looked up from the IPs, so at most RiskConnService::PLACE_LOOKUPS sources). Returns whether any was given.
     */
    private function connFilter(Request $request, $query, RiskConnService $conn): bool
    {
        $filtered = false;
        $server = $request->input('server');
        if (is_string($server) && $server !== '') {
            if (!preg_match('/^[a-z][a-z0-9]*?\d+$/', $server)) abort(500, '节点有误');
            $query->whereRaw('FIND_IN_SET(?, `servers`)', [$server]);
            $filtered = true;
        }
        $online = (int)$request->input('online');
        if ($online) {
            $query->where('last_seen_at', '>=', time() - ($online === 3600 ? 3600 : RiskConnService::ONLINE_SECONDS));
            $filtered = true;
        }
        $place = $request->input('place');
        if (is_string($place) && trim($place) !== '') {
            $nets = $conn->netsIn($query, trim($place));
            if ($nets === null) abort(500, '按地区筛选时 IP 太多（超过 ' . RiskConnService::PLACE_LOOKUPS . ' 个），请缩小日期范围或只看在线');
            $query->whereIn('ip_net', $nets);
            $filtered = true;
        }
        return $filtered;
    }

    /**
     * Today's numbers of the access log, its size, and the last write error.
     */
    public function accessStats()
    {
        return response(['data' => (new RiskAccessService())->stats()]);
    }

    /**
     * The IPs the node APIs were called from in the last 7 days that the node IP list does not cover yet (an IPv6
     * address as its /64), the latest first, with where they are: offered on the node IP list to be added.
     */
    public function nodeAuto()
    {
        $nodes = (new RiskAccessService())->autoNodes();
        $address = function (string $net) { return explode('/', $net)[0]; };
        $info = $nodes ? (new IpInfoService())->lookupMany(array_map($address, array_keys($nodes))) : [];
        $data = [];
        foreach ($nodes as $net => $seen) {
            $data[] = ['ip' => $net, 'last_seen_at' => $seen] + $this->ipInfoFields($info[$address($net)] ?? null);
        }
        return response(['data' => $data]);
    }

    public function auditFetch(Request $request)
    {
        $query = RiskAudit::query();
        $action = $request->input('action');
        if ($action !== null) {
            if (!in_array($action, self::ACTIONS, true)) abort(500, '动作有误');
            $query->where('action', $action);
        }
        if (is_string($request->input('actor_type'))) $query->where('actor_type', $request->input('actor_type'));
        if ($request->input('user_id')) $query->where('user_id', (int)$request->input('user_id'));
        $keyword = $this->keyword($request);
        if ($keyword !== null) $query->where('value', 'like', $keyword);
        return $this->paged($request, $query->orderByDesc('id'), function ($rows) {
            $ids = $rows->pluck('actor_id')->merge($rows->pluck('user_id'))->filter()->unique()->values();
            $emails = User::whereIn('id', $ids)->pluck('email', 'id');
            return $rows->map(function (RiskAudit $row) use ($emails) {
                // A 'tg' actor is a Telegram ID, not a user id
                $tg = $row->actor_type === 'tg';
                return $row->toArray() + [
                    'actor_email' => $row->actor_id && !$tg ? ($emails[$row->actor_id] ?? null) : null,
                    'actor_name' => $tg && $row->actor_id ? RiskOperator::nameOf((int)$row->actor_id) : null,
                    'user_email' => $row->user_id ? ($emails[$row->user_id] ?? null) : null,
                ];
            })->values();
        });
    }

    private function paged(Request $request, $query, ?callable $map = null, int $maxPageSize = 500)
    {
        $current = max(1, (int)$request->input('current', 1));
        $pageSize = min($maxPageSize, max(10, (int)$request->input('pageSize', 10)));
        $total = (clone $query)->count();
        $rows = $query->forPage($current, $pageSize)->get();
        return response(['data' => $map ? $map($rows) : $rows, 'total' => $total]);
    }

    /**
     * Where an IP is, shown under it in the lists: ip_location (国家 省 市, or 内网/保留地址), ip_network (the ISP or
     * IDC), ip_asn (AS37963) and ip_asn_name, null when unknown. Only shown, never matched against.
     */
    private function ipInfoFields(?array $info): array
    {
        return [
            'ip_location' => $info['location'] ?? null,
            'ip_network' => $info['network'] ?? null,
            'ip_asn' => $info['asn_number'] ?? null,
            'ip_asn_name' => $info['asn_name'] ?? null,
        ];
    }

    /**
     * The 0:00 of a Y-m-d date, or null without a valid one.
     */
    private function date($value): ?int
    {
        if (!is_string($value) || !preg_match('/^\d{4}-\d{2}-\d{2}$/', $value)) return null;
        $date = \DateTime::createFromFormat('!Y-m-d', $value);
        return $date && $date->format('Y-m-d') === $value ? $date->getTimestamp() : null;
    }

    private function validType($type): bool
    {
        return in_array($type, array_keys(RiskService::TYPES), true);
    }

    private function riskService(Request $request): RiskService
    {
        $service = new RiskService();
        return $service->actingAs('admin', (int)$request->user['id'], $service->clientIp($request));
    }

    private function user(Request $request): User
    {
        $user = User::find((int)$request->input('id'));
        if (!$user) abort(500, '用户不存在');
        return $user;
    }

    /**
     * The keyword as a LIKE pattern matching anywhere, or null without one.
     */
    private function keyword(Request $request): ?string
    {
        $keyword = $request->input('keyword');
        if (!is_string($keyword) || trim($keyword) === '') return null;
        return '%' . addcslashes(trim($keyword), '%_\\') . '%';
    }

    private function note($note): ?string
    {
        if ($note === null) return null;
        if (!is_string($note)) abort(500, '备注格式有误');
        $note = trim($note);
        if (mb_strlen($note, 'UTF-8') > 255) abort(500, '备注最多 255 个字');
        return $note === '' ? null : $note;
    }

    private function ruleIds(RiskEvent $event): array
    {
        $ids = json_decode((string)$event->indicator_ids, true);
        return is_array($ids) ? array_values(array_map('intval', $ids)) : [];
    }
}
