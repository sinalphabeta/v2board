<?php

namespace App\Plugins\RiskTelegram;

use App\Models\Plan;
use App\Models\RiskAccess;
use App\Models\RiskAudit;
use App\Models\RiskEvent;
use App\Models\RiskIndicator;
use App\Models\ServerGroup;
use App\Models\User;
use App\Services\IpInfoService;
use App\Services\RiskAccessService;
use App\Services\RiskService;
use App\Services\RiskSettings;

/**
 * The risk bot's messages (MarkdownV2) and inline keyboards. A view is ['text' => string, 'keyboard' => rows of buttons].
 *
 * Button callback data, at most 64 bytes:
 *   r:m  menu · r:u:<page> isolated users · r:e:<page> recent events · r:l:<type>:<page> indicators
 *   r:a:<page> audit log · r:h status · r:d today's report · r:c:<uid> user card · r:cr:<uid> user card as a new reply
 *   r:ue:<uid>:<s|l|o|k>:<page> a user's subscriptions, logins, orders or old links (the access log)
 *   r:n:<ip> the users of an IP, as a new reply (the IP's colons as dashes: the data is split at colons)
 *   r:i|r:<ctx>:<uid>:<eid> ask to isolate / release, r:I|R:… do it, r:x:… cancel (ctx: a alert, c user card)
 *   r:s|t:<ctx>:<uid>:<eid> ask to reset the subscription / let it through today, r:S|T:… do it
 *   r:p:<eid> ask to list the event's IP, r:P:<eid> do it · r:k:<eid> mark the alert handled
 *   r:w:<eid> ask to allowlist the event's IP, r:W:<eid> do it
 */
class RiskView
{
    public const TYPES = RiskService::TYPES;
    private const EVENT_TYPES = ['subscription' => '订阅', 'login' => '登录', 'register' => '注册', 'identity' => '命中'] + RiskService::FINDING_TYPES;
    private const ACTIONS = [
        'add' => '新增', 'edit' => '编辑', 'delete' => '删除', 'mark' => '隔离用户', 'unmark' => '解除隔离', 'setting' => '修改设置',
        'reset' => '重置订阅', 'exempt' => '今天放行',
    ];
    // Settings edited on the admin panel (RiskSettings)
    public const SETTINGS = [
        'bot_token' => 'Bot Token', 'alert_chat_id' => '告警群 Chat ID', 'bot_operators' => '可操作的 Telegram ID', 'honeypot_group_id' => '蜜罐权限组',
        'ip_info_enabled' => '告警带 IP 归属', 'asn_cache_ttl' => 'ASN 缓存时间', 'trusted_proxies' => '可信代理',
        'access_log_enabled' => '访问记录', 'access_log_days' => '访问记录保留天数', 'sub_daily_limit' => '每天订阅上限',
        'link_detection' => '关联检测', 'link_ip_users' => '同 IP 多用户阈值', 'daily_report' => '每晚日报',
        'alert_daily_limit' => '每类告警每天上限', 'sub_burst_limit' => '10 分钟订阅次数告警',
    ];
    // How an access log row's result shows, when it is not ok
    private const ACCESS_RESULTS = ['failed' => '密码错误', 'isolated' => '蜜罐', 'unavailable' => '不可用', 'limited' => '超限'];
    private const FIELDS = ['value' => '值', 'note' => '备注', 'enabled' => '启用'];
    // Audit changes that the action itself already says
    private const IMPLIED = ['add' => ['value', 'enabled'], 'delete' => ['enabled']];
    private const PAGE_SIZE = 10;
    // The nodes' exit IPs, read once per view
    private $nodes;

    public function menu(): array
    {
        $counts = $this->indicatorCounts();
        $rules = array_sum(array_intersect_key($counts, array_flip(RiskService::RULE_TYPES)));
        $text = "🛡 *风控菜单*\n已隔离 " . User::where('risk_status', RiskService::STATUS_RISK)->count() . ' 人 · 24 小时事件 ' .
            RiskEvent::where('last_seen_at', '>=', time() - 86400)->count() . " 条 · 名单 {$rules} 条 · 白名单 {$counts['allow_ip']} 条";
        return $this->view($text, [
            [$this->button('👥 风险用户', 'r:u:1'), $this->button('⚡ 最近事件', 'r:e:1')],
            [$this->button('📧 邮箱名单', 'r:l:email:1'), $this->button('🌐 IP 名单', 'r:l:ip:1')],
            [$this->button('🧩 UA 名单', 'r:l:ua:1'), $this->button('🏢 ASN 名单', 'r:l:asn:1')],
            [$this->button('🟢 IP 白名单', 'r:l:allow_ip:1'), $this->button('📊 今日概况', 'r:d')],
            [$this->button('📝 操作记录', 'r:a:1'), $this->button('🩺 系统状态', 'r:h')],
        ]);
    }

    public function riskUsers(int $page): array
    {
        $query = User::where('risk_status', RiskService::STATUS_RISK)->orderByDesc('risk_marked_at')->orderBy('id');
        [$users, $page, $pages, $total] = $this->paginate($query, $page);
        $lines = [];
        $buttons = [];
        foreach ($users->values() as $i => $user) {
            $number = ($page - 1) * self::PAGE_SIZE + $i + 1;
            $lines[] = $number . '\\. ' . $this->code($user->email) . ' · uid ' . $this->code($user->id) . ' · ' .
                $this->escape($this->time($user->risk_marked_at));
            $buttons[] = $this->button($number . '. ' . $this->shorten($user->email, 28), "r:c:{$user->id}");
        }
        $text = "👥 *已隔离的用户*\n共 {$total} 个 · 第 {$page}/{$pages} 页\n\n" . ($lines ? implode("\n", $lines) : '暂无');
        return $this->view($text, array_merge(array_chunk($buttons, 2), [$this->pager('r:u:', $page, $pages)]));
    }

    public function events(int $page): array
    {
        $query = RiskEvent::orderByDesc('last_seen_at')->orderByDesc('id');
        [$events, $page, $pages, $total] = $this->paginate($query, $page);
        $emails = User::whereIn('id', $events->pluck('user_id')->filter()->unique()->values())->pluck('email', 'id');
        $lines = $events->map(function (RiskEvent $event) use ($emails) {
            $user = $event->user_id ? $this->code($emails[$event->user_id] ?? 'uid ' . $event->user_id) : '\\-';
            return $this->code($this->time($event->last_seen_at)) . ' · ' . $this->escape($this->eventType($event->event_type)) .
                ' · ' . $user . ' · ' . $this->code($event->ip) . ' · x' . (int)$event->occurrences;
        })->all();
        $buttons = $emails->map(function ($email, $id) {
            return $this->button('👤 ' . $this->shorten($email, 26), "r:c:{$id}");
        })->values()->all();
        $text = "⚡ *最近事件*\n共 {$total} 条 · 第 {$page}/{$pages} 页\n\n" . ($lines ? implode("\n", $lines) : '暂无');
        return $this->view($text, array_merge(array_chunk($buttons, 2), [$this->pager('r:e:', $page, $pages)]));
    }

    public function indicators(string $type, int $page): array
    {
        if (!isset(self::TYPES[$type])) $type = 'email';
        $query = RiskIndicator::where('type', $type)->where('enabled', 1)->orderBy('value');
        [$indicators, $page, $pages, $total] = $this->paginate($query, $page, $type === 'ua' ? 10 : 20);
        $lines = $indicators->map(function (RiskIndicator $indicator) {
            return '• ' . $this->code($indicator->value) .
                ($indicator->note ? ' — ' . $this->escape($this->shorten($indicator->note, 40)) : '');
        })->all();
        $about = $type === 'allow_ip' ? "\n" . $this->escape('这些 IP 命中 IP、ASN 名单不告警，UA、邮箱名单照常') : '';
        $text = '📋 *' . $this->escape(RiskService::LIST_NAMES[$type]) . "*{$about}\n共 {$total} 条 · 第 {$page}/{$pages} 页\n\n" .
            ($lines ? implode("\n", $lines) : '暂无');
        return $this->view($text, [$this->pager("r:l:{$type}:", $page, $pages)]);
    }

    public function audit(int $page): array
    {
        [$rows, $page, $pages, $total] = $this->paginate(RiskAudit::orderByDesc('id'), $page);
        $lines = $rows->map(function (RiskAudit $row) { return $this->auditLine($row); })->all();
        $text = "📝 *操作记录*\n共 {$total} 条 · 第 {$page}/{$pages} 页\n\n" . ($lines ? implode("\n\n", $lines) : '暂无');
        return $this->view($text, [$this->pager('r:a:', $page, $pages)]);
    }

    public function health(): array
    {
        $risk = new RiskService();
        $honeypot = (int)RiskSettings::get('honeypot_group_id');
        $group = $honeypot > 0 ? ServerGroup::find($honeypot) : null;
        $counts = $this->indicatorCounts();
        $asnAvailable = (new IpInfoService())->asnDatabaseAvailable();
        $lines = [
            '🩺 *风控状态*',
            '蜜罐权限组：' . ($honeypot > 0 ? $this->code($honeypot) . ($group ? ' ' . $this->escape($group->name) : ' ⚠️ 不存在') : '未配置'),
            '告警群：' . (RiskSettings::get('alert_chat_id') ? '已配置' : '未配置'),
            '可操作的人：' . (count(RiskOperator::listed())
                ? count(RiskOperator::listed()) . ' 个 Telegram ID'
                : $this->escape('⚠️ 没设置（绑定了 Telegram 的管理员都能操作）：在风控概览里填「可操作的 Telegram ID」')),
            '启用的名单：' . collect(RiskService::RULE_TYPES)->map(function ($type) use ($counts) {
                return self::TYPES[$type] . ' ' . $counts[$type];
            })->implode(' · '),
            'IP 白名单：' . $counts['allow_ip'],
            '已隔离用户：' . User::where('risk_status', RiskService::STATUS_RISK)->count(),
            '24 小时事件：' . RiskEvent::where('last_seen_at', '>=', time() - 86400)->count(),
            'ASN 数据库：' . ($asnAvailable ? '可用' : '不可用'),
        ];
        $stats = $risk->access()->stats();
        $lines[] = '';
        $lines[] = '访问记录：' . ($stats['enabled'] ? '开' : '⚠️ 已关闭') . $this->escape(' · 保留 ' . $stats['days'] . ' 天 · ' .
            $this->tableSize($stats['table_rows'], $stats['table_bytes']));
        $lines[] = '今天：' . $this->escape($stats['rows_today'] . ' 行 · 最后写入 ' . $this->time($stats['last_write_at'], 'H:i:s') .
            ' · 非公网 IP ' . $this->percent($stats['private_rows_today'], $stats['rows_today']));
        $lastError = $stats['last_error'];
        $lines[] = '写入失败：今天 ' . $stats['errors_today'] . ' 次' . ($lastError ? $this->escape('，最近一次 ' .
            $this->time($lastError['at'] ?? null, 'm-d H:i')) . ' ' . $this->code($this->shorten($lastError['message'] ?? '', 80)) : '');
        $lines[] = '订阅上限：' . $this->escape($stats['daily_limit'] ? $stats['daily_limit'] . ' 次/天，超过返回 429' : '不限');
        $burst = (int)RiskSettings::get('sub_burst_limit');
        $lines[] = '订阅过频：' . $this->escape($burst > 0 ? "10 分钟 {$burst} 次起报（只告警）" : '不检测');
        $lines[] = '节点出口 IP：' . $stats['nodes'] . $this->escape(' 个（' . RiskAccessService::NODE_DAYS . ' 天内调过面板接口的）');
        $lines[] = '关联检测：' . (RiskSettings::get('link_detection') ? '开 · 同 IP ' . (int)RiskSettings::get('link_ip_users') . ' 人起报' : '关') .
            ' · 每晚日报：' . (RiskSettings::get('daily_report') ? '开' : '关');
        $alerts = $risk->alerts()->dayCounts();
        $lines[] = $this->escape('告警：每类每天最多 ' . $risk->alerts()->dailyLimit() . " 条 · 今天合并 {$alerts['merged']} 条 · 超出上限没发 {$alerts['skipped']} 条");
        $mixed = $risk->mixedHoneypotNodes();
        if ($mixed) $lines[] = "\n⚠️ 这些节点同时属于蜜罐组和普通组：" . $this->escape(implode(', ', $mixed));
        if ($honeypot > 0 && !$group) $lines[] = "\n⚠️ 蜜罐权限组不存在：被隔离的用户拿不到任何节点";
        if ($counts['asn'] && !$asnAvailable) $lines[] = "\n⚠️ 有 ASN 名单但 ASN 数据库不可用";
        if ($stats['rows_today'] >= 20 && $stats['private_rows_today'] * 2 > $stats['rows_today']) {
            $lines[] = "\n⚠️ 今天的访问记录大多是内网 IP：可信代理可能没配好，记下的是反代的地址";
        }
        return $this->view(implode("\n", $lines), [[$this->button('🏠 菜单', 'r:m')]]);
    }

    public function help(): array
    {
        $sections = [
            '常用' => [
                '/menu  打开菜单（按钮操作）',
                '/search 邮箱、uid 或 IP  查询用户',
                '/add 邮箱…  隔离：把邮箱加入名单',
                '/del 邮箱…  解除：停用邮箱名单',
            ],
            '名单' => [
                '/addip、/delip、/listip  IP 或 CIDR',
                '/addua、/delua、/listua  UA 关键字',
                '/addasn、/delasn、/listasn  AS 号',
                '/addallow、/delallow、/listallow  IP 白名单：命中 IP、ASN 名单不告警',
                '/list  邮箱名单',
                '/edit 值或ID 备注  修改备注',
            ],
            '查看' => [
                '/riskusers  已隔离的用户',
                '/events  最近事件',
                '/report  今日概况：访问、告警和要留意的用户（每晚 00:05 发前一天的日报）',
                '/audit  操作记录',
                '/health  风控状态',
                '/id  我的 Telegram ID（在群里还有群的 Chat ID）',
            ],
        ];
        $text = '*风控 Bot 帮助*';
        foreach ($sections as $title => $lines) {
            $text .= "\n\n*" . $this->escape($title) . "*\n" . implode("\n", array_map(function ($line) {
                return $this->escape($line);
            }, $lines));
        }
        $text .= "\n\n" . $this->escape('回复一条告警或用户卡片发 /add、/del、/search，回复一条告警发 /addip、/delip、/addallow，可以不写参数。') .
            "\n" . $this->escape('用户卡片和告警上的「重置订阅」会换掉订阅链接和 UUID，分享出去的立刻失效；用户本人要重新导入订阅。');
        return $this->view($text, [[$this->button('🏠 菜单', 'r:m')]]);
    }

    public function userCard(User $user): array
    {
        $plan = $user->plan_id ? Plan::find($user->plan_id) : null;
        $used = ((int)$user->u + (int)$user->d) / 1073741824;
        $total = (int)$user->transfer_enable / 1073741824;
        $lines = [
            '👤 *用户详情*',
            '邮箱: ' . $this->code($user->email),
            'uid: ' . $this->code($user->id),
            '注册时间: ' . $this->escape($user->created_at ? date('Y-m-d H:i:s', (int)$user->created_at) : '-'),
            '套餐: ' . $this->escape($plan ? $plan->name : '无订阅'),
            '流量: ' . $this->escape(number_format($used, 2) . ' / ' . number_format($total, 2) . ' GB'),
            '到期时间: ' . $this->escape($user->expired_at === null ? '长期有效' : date('Y-m-d H:i:s', (int)$user->expired_at)),
            '权限组: ' . $this->escape($user->group_id ?? '-'),
            '风险状态: ' . $this->riskStatus($user),
            '今天订阅: ' . $this->escape($this->todayLine($user)),
        ];
        $registration = (new RiskAccessService())->registration($user);
        if ($registration) $lines[] = '注册 IP: ' . $this->code($registration->ip);
        $old = (new RiskAccessService())->oldLinks($user);
        if ($old) {
            $lines[] = '重置后旧链接: ' . $this->escape('近 ' . RiskAccessService::OLD_LINK_DAYS . " 天 {$old[0]} 次 · {$old[1]} 个 IP · 最后 " .
                $this->time($old[2]));
        }
        $lines = array_merge($lines, [
            '',
            '*最近订阅*',
            $this->accessLines($user, 'subscription', 5),
            '',
            '*最近登录*',
            $this->accessLines($user, 'login', 5),
        ]);
        return $this->view(implode("\n", $lines), $this->cardKeyboard($user));
    }

    public function cardKeyboard(User $user): array
    {
        $rows = [[
            $this->isolated($user) ? $this->button('🔓 解除隔离', "r:r:c:{$user->id}") : $this->button('🔒 隔离', "r:i:c:{$user->id}"),
            $this->button('♻️ 重置订阅', "r:s:c:{$user->id}"),
        ]];
        if ($this->limitedToday($user)) $rows[] = [$this->button('✅ 今天放行', "r:t:c:{$user->id}")];
        $rows[] = [
            $this->button('📜 订阅记录', "r:ue:{$user->id}:s:1"), $this->button('🔑 登录记录', "r:ue:{$user->id}:l:1"),
            $this->button('🛒 下单记录', "r:ue:{$user->id}:o:1"),
        ];
        // Clients still updating with a link from before a reset: the user's own, or whoever it was shared with
        if ((new RiskAccessService())->oldLinks($user)) $rows[] = [$this->button('🔗 旧链接记录', "r:ue:{$user->id}:k:1")];
        $rows[] = [$this->button('🏠 菜单', 'r:m')];
        return $rows;
    }

    /**
     * A user's subscriptions ('s'), logins ('l'), orders ('o') or old links ('k') from the access log, one row per day,
     * IP and client.
     */
    public function userEvents(User $user, string $kind, int $page): array
    {
        $kinds = ['s' => ['subscription', '📜 *订阅记录*'], 'l' => ['login', '🔑 *登录记录*'], 'o' => ['order', '🛒 *下单记录*'],
            'k' => ['old_link', '🔗 *旧链接记录*']];
        [$type, $title] = $kinds[$kind] ?? $kinds['s'];
        [$rows, $page, $pages, $total] = (new RiskAccessService())->userPage($user, $type, $page, self::PAGE_SIZE);
        $text = $title . ' ' . $this->code($user->email) . "\n共 {$total} 条 · 第 {$page}/{$pages} 页\n" .
            $this->escape('最后一次 | IP | 客户端 | 当天次数') . "\n\n" .
            ($rows->count() ? $rows->map(function (RiskAccess $row) { return $this->accessLine($row); })->implode("\n") : '暂无');
        $pager = $this->pager("r:ue:{$user->id}:{$kind}:", $page, $pages);
        $pager[array_search('r:m', array_column($pager, 'callback_data'), true)] = $this->button('👤 返回用户', "r:c:{$user->id}");
        return $this->view($text, [$pager]);
    }

    /**
     * Users found for a query; for an IP with what each did from it ($usage: see RiskService::ipUsage()).
     */
    public function searchResults($users, string $query, array $usage = []): array
    {
        $byIp = (bool)filter_var($query, FILTER_VALIDATE_IP);
        $days = (new RiskService())->searchDays();
        $note = $byIp ? "\n" . $this->escape("最近 {$days} 天" . (strpos($query, ':') !== false ? '，IPv6 按它所在的 /64 查' : '')) : '';
        if (!$users->count()) return $this->view('未找到：' . $this->code($query) . $note, []);
        $lines = [];
        $buttons = [];
        foreach ($users->values() as $i => $user) {
            $line = ($i + 1) . '\\. ' . $this->code($user->email) . ' · uid ' . $this->code($user->id) .
                ($this->isolated($user) ? ' · 🔒 已隔离' : '');
            if (isset($usage[$user->id])) $line .= "\n" . $this->escape('   ' . $this->usageText($usage[$user->id]));
            $lines[] = $line;
            $buttons[] = [$this->button(($i + 1) . '. ' . $this->shorten($user->email, 40), "r:c:{$user->id}")];
        }
        $text = '🔎 *查询* ' . $this->code($query) . "\n共 {$users->count()} 个用户" . $note . "\n\n" . implode("\n", $lines);
        return $this->view($text, $buttons);
    }

    /**
     * Buttons under an alert about a user. A public IP in neither the IP list (as itself or in a range) nor the
     * allowlist can be added to the IP list or allowlisted, on its own row so as not to be taken for the other; one in
     * a listed range can still be let through by replying /addallow. Alerts of what a check found
     * (RiskService::FINDING_TYPES) also offer what fits them: the IP's users, 今天放行, 重置订阅.
     */
    public function alertKeyboard(User $user, ?RiskEvent $event): array
    {
        $eventId = $event ? $event->id : '';
        $rows = [[
            $this->isolated($user)
                ? $this->button('🔓 解除隔离', "r:r:a:{$user->id}:{$eventId}")
                : $this->button('🔒 隔离', "r:i:a:{$user->id}:{$eventId}"),
            $this->button('🔍 详情', "r:cr:{$user->id}"),
        ]];
        if ($event) {
            $finding = [];
            if (in_array($event->event_type, ['ip_users', 'register_link'], true) && filter_var($event->ip, FILTER_VALIDATE_IP)) {
                $finding[] = $this->button('🔎 这个 IP 的用户', 'r:n:' . str_replace(':', '-', (string)$event->ip));
            }
            if ($event->event_type === 'sub_limit' && $this->limitedToday($user)) {
                $finding[] = $this->button('✅ 今天放行', "r:t:a:{$user->id}:{$eventId}");
            }
            if (in_array($event->event_type, ['sub_limit', 'ip_users', 'sub_burst'], true)) {
                $finding[] = $this->button('♻️ 重置订阅', "r:s:a:{$user->id}:{$eventId}");
            }
            if ($finding) $rows[] = $finding;
            $risk = new RiskService();
            $ip = (string)$event->ip;
            $open = $risk->allowRangeFor($ip) !== null && !$risk->allowEntryFor($ip) && !$risk->ipEntryFor($ip);
            $second = [];
            if ($open) $second[] = $this->button('➕ IP 加入名单', "r:p:{$event->id}");
            $second[] = $this->button('✅ 已处理', "r:k:{$event->id}");
            $rows[] = $second;
            if ($open) $rows[] = [$this->button('🟢 放行此 IP（白名单）', "r:w:{$event->id}")];
        }
        return $rows;
    }

    /**
     * The daily report (or today's so far): the numbers of RiskLinkService::report() and the users to look at, each
     * with a button to their card. $menu: a 🏠 菜单 button as well, when it replaces the menu message.
     */
    public function report(array $data, bool $menu): array
    {
        $partial = $data['to'] > time() - 60;
        $title = $partial ? '📊 *今日概况* ' . $this->escape(date('m-d', $data['from']) . ' 截至 ' . date('H:i', min($data['to'], time())))
            : '📊 *风控日报* ' . $this->escape(date('m-d', $data['from']));
        $lines = [
            $title,
            $this->escape("活跃 {$data['active']} 人 · 订阅 {$data['subscriptions']} 次 · 登录 {$data['logins']}（密码错误 {$data['failed_logins']}）· " .
                "注册 {$data['registrations']} · 下单 {$data['orders']} · 支付 {$data['paid']}"),
            $this->escape("风险事件 {$data['events']} 条 · 新隔离 {$data['isolated']} 人 · 订阅超限 {$data['limited']} 人 · " .
                "订阅过频 {$data['bursts']} 人 · " .
                "关联告警 {$data['link_alerts']} 条" . ($data['merged_alerts'] || $data['skipped_alerts']
                    ? "（合并 {$data['merged_alerts']} 条、超出每天上限没发 {$data['skipped_alerts']} 条）" : '')),
        ];
        $users = [];
        $user = function (array $row) use (&$users): string {
            $users[$row['user_id']] = $row['email'] ?? null;
            return 'uid ' . $this->code($row['user_id']) . ($row['email'] ? ' ' . $this->code($this->shorten($row['email'], 28)) : '');
        };
        $sections = [
            '订阅最多' => array_map(function ($row) use ($user) {
                return $user($row) . $this->escape(" {$row['total']} 次 · {$row['ips']} 个 IP · {$row['clients']} 个客户端");
            }, $data['top_subscribers']),
            '同 IP 多用户' => array_map(function ($row) {
                $where = trim(($row['location'] ?? '') . ' ' . ($row['network'] ?? ''));
                return $this->code($row['ip_net']) . ($where !== '' ? ' ' . $this->escape($where) : '') .
                    $this->escape(" · {$row['users']} 人" . ($row['isolated'] ? "（含已隔离 {$row['isolated']}）" : ''));
            }, $data['shared_ips']),
            '多地区' => array_map(function ($row) use ($user) {
                return $user($row) . $this->escape(" {$row['places']} 个地区 · {$row['asns']} 个 ASN");
            }, $data['regions']),
            '密码错误最多' => array_map(function ($row) use ($user) {
                return $user($row) . $this->escape(" {$row['total']} 次 · {$row['ips']} 个 IP");
            }, $data['failed']),
            '可疑客户端' => array_map(function ($row) use ($user) {
                $ua = trim($row['user_agent']);
                return $user($row) . ' ' . $this->code($ua === '' ? '空 UA' : $this->shorten($ua, 32)) . $this->escape(" {$row['total']} 次");
            }, $data['scripts']),
            '旧链接还在被拉' => array_map(function ($row) use ($user) {
                return $user($row) . $this->escape(" {$row['total']} 次 · {$row['ips']} 个 IP");
            }, $data['old_links'] ?? []),
        ];
        foreach ($sections as $name => $rows) {
            if ($rows) $lines[] = "\n*" . $this->escape($name) . "*\n" . implode("\n", $rows);
        }
        $lines[] = "\n" . $this->escape('访问记录 ' . $this->tableSize($data['table_rows'], $data['table_bytes']) . " · 保留 {$data['days']} 天" .
            ($data['errors'] ? " · 写入失败 {$data['errors']} 次" : ''));
        $buttons = [];
        foreach (array_slice($users, 0, 8, true) as $id => $email) {
            $buttons[] = $this->button('👤 ' . ($email ? $this->shorten($email, 20) : "uid {$id}"), "r:cr:{$id}");
        }
        $keyboard = array_chunk($buttons, 2);
        if ($menu) $keyboard[] = [$this->button('🏠 菜单', 'r:m')];
        return $this->view(implode("\n", $lines), $keyboard);
    }

    public function confirmKeyboard(string $label, string $confirm, string $cancel): array
    {
        return [[$this->button('✅ ' . $label, $confirm), $this->button('取消', $cancel)]];
    }

    /**
     * What /add, /del and the other list commands report: [label => values] for 新增, 已存在 and so on.
     */
    public function result(array $groups, array $notes = []): string
    {
        $text = '*操作完成*';
        foreach ($groups as $label => $values) {
            if ($values) $text .= "\n\n" . $label . ' ' . count($values) . " 条:\n" . $this->bulletList($values);
        }
        foreach ($notes as $note) $text .= "\n\n" . $note;
        return $text;
    }

    public function auditLine(RiskAudit $row): string
    {
        $parts = [$this->code($this->time($row->created_at, 'm-d H:i:s')), $this->escape(self::ACTIONS[$row->action] ?? $row->action)];
        if ($row->user_id) $parts[] = 'uid ' . $this->code((int)$row->user_id);
        $parts[] = $row->action === 'setting'
            ? $this->escape('设置 ' . (self::SETTINGS[$row->value] ?? $row->value))
            : $this->escape(self::TYPES[$row->type] ?? $row->type) . ' ' . $this->code($this->shorten($row->value, 60));
        $parts[] = $this->actor($row);
        $line = implode(' \\| ', $parts);
        $changes = [];
        foreach ((array)$row->changes as $field => $change) {
            if (!isset(self::FIELDS[$field]) || in_array($field, self::IMPLIED[$row->action] ?? [], true)) continue;
            $changes[] = self::FIELDS[$field] . ': ' . $this->changeValue($field, $change[0] ?? null) .
                ' → ' . $this->changeValue($field, $change[1] ?? null);
        }
        // Why the system made the change, e.g. an IP indicator disabled by the allowlist entry covering it
        $reason = $row->changes['reason'] ?? null;
        if (is_string($reason)) $changes[] = '原因: ' . $this->escape($reason);
        return $changes ? $line . "\n" . implode('；', $changes) : $line;
    }

    public function escape($value): string
    {
        return preg_replace_callback('/[_*\[\]()~`>#+\-=|{}.!\\\\]/', function ($match) {
            return '\\' . $match[0];
        }, (string)$value);
    }

    public function code($value): string
    {
        return '`' . str_replace(['\\', '`'], ['\\\\', '\\`'], (string)$value) . '`';
    }

    public function bulletList(array $values): string
    {
        return implode("\n", array_map(function ($value) { return '• ' . $this->code($value); }, $values));
    }

    public function shorten($value, int $length): string
    {
        $value = (string)$value;
        return mb_strlen($value, 'UTF-8') > $length ? mb_substr($value, 0, $length, 'UTF-8') . '…' : $value;
    }

    public function isolated(User $user): bool
    {
        return (int)$user->risk_status === RiskService::STATUS_RISK;
    }

    private function riskStatus(User $user): string
    {
        if (!$this->isolated($user)) return '✅ 正常';
        $indicator = $user->risk_indicator_id ? RiskIndicator::find($user->risk_indicator_id) : null;
        return '🔒 已隔离（' . $this->escape($this->time($user->risk_marked_at)) .
            ($indicator ? '，名单 ' . $this->code($indicator->value) : '') . '）';
    }

    private function accessLines(User $user, string $type, int $limit): string
    {
        [$rows] = (new RiskAccessService())->userPage($user, $type, 1, $limit);
        return $rows->count() ? $rows->map(function (RiskAccess $row) { return $this->accessLine($row); })->implode("\n") : '无记录';
    }

    /**
     * An access log row: its last time, the IP (节点: a node's exit IP), the client, how many times that day, and the
     * result unless ok (e.g. 密码错误).
     */
    private function accessLine(RiskAccess $row): string
    {
        if ($this->nodes === null) $this->nodes = (new RiskAccessService())->nodeNets();
        $nodes = $this->nodes;
        $ua = trim(preg_replace('/\s+/', ' ', (string)$row->user_agent));
        $results = array_flip(RiskAccessService::RESULTS);
        // An old link is always refused: its result says nothing more
        $result = (int)$row->event_type === RiskAccessService::TYPES['old_link'] ? null : (self::ACCESS_RESULTS[$results[$row->result] ?? 'ok'] ?? null);
        $ip = $this->code($row->ip) . ($row->ip_net === '' ? ' ' . $this->escape('（当天请求太多，之后的都合在这一行）') : '') .
            ($row->ip_net !== '' && isset($nodes[$row->ip_net]) ? ' 节点' : '');
        return $this->code($this->time($row->last_seen_at, 'm-d H:i')) . ' \\| ' . $ip . ' \\| ' .
            $this->code($ua === '' ? '空 UA' : $this->shorten($ua, 40)) . ' \\| x' . (int)$row->occurrences .
            ($result ? ' · ' . $this->escape($result) : '');
    }

    private function todayLine(User $user): string
    {
        $access = new RiskAccessService();
        $limit = $access->dailyLimit();
        return $access->subscriptionsToday($user) . ' 次' . ($limit ? "（上限 {$limit}）" : '') .
            ($access->exempt($user) ? ' · 今天已放行' : '') . ($this->limitedToday($user) ? ' · ⛔ 已超限' : '');
    }

    /**
     * Whether the user's subscriptions are refused for the rest of today: over the limit, not isolated, not let through.
     */
    private function limitedToday(User $user): bool
    {
        $access = new RiskAccessService();
        return $access->overLimit($user, $access->subscriptionsToday($user));
    }

    /**
     * What a user did from an IP, e.g. 订阅 20 次 · 登录 1 次 · 最后 10-15 12:30.
     */
    private function usageText(array $usage): string
    {
        $parts = [];
        foreach (RiskAccessService::TYPE_NAMES as $type => $name) {
            if (!empty($usage[$type])) $parts[] = "{$name} {$usage[$type]} 次";
        }
        if (!empty($usage['last_seen_at'])) $parts[] = '最后 ' . $this->time($usage['last_seen_at']);
        return implode(' · ', $parts);
    }

    private function tableSize(?int $rows, ?int $bytes): string
    {
        if ($rows === null || $bytes === null) return '大小未知';
        $size = $bytes < 1048576 ? max(1, round($bytes / 1024)) . ' KB' : number_format($bytes / 1048576, 1) . ' MB';
        return '约 ' . number_format($rows) . ' 行 / ' . $size;
    }

    private function percent(int $part, int $total): string
    {
        return $total ? round($part * 100 / $total) . '%' : '-';
    }

    /**
     * The number of enabled indicators of each type.
     */
    private function indicatorCounts(): array
    {
        $counts = RiskIndicator::where('enabled', 1)->selectRaw('type, COUNT(*) AS total')->groupBy('type')->pluck('total', 'type');
        $result = [];
        foreach (array_keys(self::TYPES) as $type) $result[$type] = (int)($counts[$type] ?? 0);
        return $result;
    }

    private function eventType($type): string
    {
        return self::EVENT_TYPES[$type] ?? (string)$type;
    }

    private function actor(RiskAudit $row): string
    {
        if ($row->actor_type === 'admin') return '管理端 uid ' . $this->code((int)$row->actor_id);
        if ($row->actor_type === 'bot') return 'Bot uid ' . $this->code((int)$row->actor_id);
        if ($row->actor_type === 'tg') return 'Bot ' . $this->escape(RiskOperator::nameOf((int)$row->actor_id));
        if ($row->actor_type === 'api') return 'API' . ($row->actor_ip ? ' ' . $this->code($row->actor_ip) : '');
        if ($row->actor_type === 'system') return '系统';
        return '未知';
    }

    private function changeValue(string $field, $value): string
    {
        if ($value === null || $value === '') return '空';
        if ($field === 'enabled' || is_bool($value)) return $value ? '是' : '否';
        return $this->code($this->shorten($value, 60));
    }

    private function time($timestamp, string $format = 'm-d H:i'): string
    {
        return $timestamp ? date($format, (int)$timestamp) : '-';
    }

    private function pager(string $prefix, int $page, int $pages): array
    {
        $row = [];
        if ($page > 1) $row[] = $this->button('⬅️ 上一页', $prefix . ($page - 1));
        $row[] = $this->button('🏠 菜单', 'r:m');
        if ($page < $pages) $row[] = $this->button('下一页 ➡️', $prefix . ($page + 1));
        return $row;
    }

    private function paginate($query, int $page, int $size = self::PAGE_SIZE): array
    {
        $total = (clone $query)->count();
        $pages = max(1, (int)ceil($total / $size));
        $page = min(max(1, $page), $pages);
        return [$query->forPage($page, $size)->get(), $page, $pages, $total];
    }

    private function button(string $text, string $data): array
    {
        return ['text' => $text, 'callback_data' => $data];
    }

    private function view(string $text, array $keyboard): array
    {
        return ['text' => $text, 'keyboard' => $keyboard];
    }
}
