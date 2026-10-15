<?php

namespace App\Plugins\RiskTelegram;

use App\Models\Plan;
use App\Models\RiskAudit;
use App\Models\RiskEvent;
use App\Models\RiskIndicator;
use App\Models\ServerGroup;
use App\Models\User;
use App\Services\IpInfoService;
use App\Services\RiskService;
use App\Services\RiskSettings;

/**
 * The risk bot's messages (MarkdownV2) and inline keyboards. A view is ['text' => string, 'keyboard' => rows of buttons].
 *
 * Button callback data, at most 64 bytes:
 *   r:m  menu · r:u:<page> isolated users · r:e:<page> recent events · r:l:<type>:<page> indicators
 *   r:a:<page> audit log · r:h status · r:c:<uid> user card · r:cr:<uid> user card as a new reply
 *   r:ue:<uid>:<s|l>:<page> a user's subscriptions or logins
 *   r:i|r:<ctx>:<uid>:<eid> ask to isolate / release, r:I|R:… do it, r:x:… cancel (ctx: a alert, c user card)
 *   r:p:<eid> ask to list the event's IP, r:P:<eid> do it · r:k:<eid> mark the alert handled
 *   r:w:<eid> ask to allowlist the event's IP, r:W:<eid> do it
 */
class RiskView
{
    public const TYPES = RiskService::TYPES;
    private const EVENT_TYPES = ['subscription' => '订阅', 'login' => '登录', 'register' => '注册', 'identity' => '命中'];
    private const ACTIONS = ['add' => '新增', 'edit' => '编辑', 'delete' => '删除', 'mark' => '隔离用户', 'unmark' => '解除隔离', 'setting' => '修改设置'];
    // Settings edited on the admin panel (RiskSettings)
    public const SETTINGS = [
        'bot_token' => 'Bot Token', 'alert_chat_id' => '告警群 Chat ID', 'honeypot_group_id' => '蜜罐权限组',
        'ip_info_enabled' => '告警带 IP 归属', 'asn_cache_ttl' => 'ASN 缓存时间', 'trusted_proxies' => '可信代理',
    ];
    private const FIELDS = ['value' => '值', 'note' => '备注', 'enabled' => '启用'];
    // Audit changes that the action itself already says
    private const IMPLIED = ['add' => ['value', 'enabled'], 'delete' => ['enabled']];
    private const PAGE_SIZE = 10;

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
            [$this->button('🟢 IP 白名单', 'r:l:allow_ip:1')],
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
            '启用的名单：' . collect(RiskService::RULE_TYPES)->map(function ($type) use ($counts) {
                return self::TYPES[$type] . ' ' . $counts[$type];
            })->implode(' · '),
            'IP 白名单：' . $counts['allow_ip'],
            '已隔离用户：' . User::where('risk_status', RiskService::STATUS_RISK)->count(),
            '24 小时事件：' . RiskEvent::where('last_seen_at', '>=', time() - 86400)->count(),
            'ASN 数据库：' . ($asnAvailable ? '可用' : '不可用'),
        ];
        $mixed = $risk->mixedHoneypotNodes();
        if ($mixed) $lines[] = "\n⚠️ 这些节点同时属于蜜罐组和普通组：" . $this->escape(implode(', ', $mixed));
        if ($honeypot > 0 && !$group) $lines[] = "\n⚠️ 蜜罐权限组不存在：被隔离的用户拿不到任何节点";
        if ($counts['asn'] && !$asnAvailable) $lines[] = "\n⚠️ 有 ASN 名单但 ASN 数据库不可用";
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
        $text .= "\n\n" . $this->escape('回复一条告警或用户卡片发 /add、/del、/search，回复一条告警发 /addip、/delip、/addallow，可以不写参数。');
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
            '',
            '*最近订阅*',
            $this->eventLines($user, 'subscription', 5),
            '',
            '*最近登录*',
            $this->eventLines($user, 'login', 5),
        ];
        return $this->view(implode("\n", $lines), $this->cardKeyboard($user));
    }

    public function cardKeyboard(User $user): array
    {
        return [
            [$this->isolated($user) ? $this->button('🔓 解除隔离', "r:r:c:{$user->id}") : $this->button('🔒 隔离', "r:i:c:{$user->id}")],
            [$this->button('📜 订阅记录', "r:ue:{$user->id}:s:1"), $this->button('🔑 登录记录', "r:ue:{$user->id}:l:1")],
            [$this->button('🏠 菜单', 'r:m')],
        ];
    }

    public function userEvents(User $user, string $kind, int $page): array
    {
        $type = $kind === 'l' ? 'login' : 'subscription';
        $query = RiskEvent::where('user_id', $user->id)->where('event_type', $type)->orderByDesc('last_seen_at')->orderByDesc('id');
        [$events, $page, $pages, $total] = $this->paginate($query, $page);
        $text = ($kind === 'l' ? '🔑 *登录记录*' : '📜 *订阅记录*') . ' ' . $this->code($user->email) .
            "\n共 {$total} 条 · 第 {$page}/{$pages} 页\n时间 \\| IP \\| UA \\| 次数\n\n" .
            ($events->count() ? $events->map(function (RiskEvent $event) { return $this->eventLine($event); })->implode("\n") : '暂无');
        $pager = $this->pager("r:ue:{$user->id}:{$kind}:", $page, $pages);
        $pager[array_search('r:m', array_column($pager, 'callback_data'), true)] = $this->button('👤 返回用户', "r:c:{$user->id}");
        return $this->view($text, [$pager]);
    }

    public function searchResults($users, string $query): array
    {
        $byIp = (bool)filter_var($query, FILTER_VALIDATE_IP);
        $note = $byIp ? "\n" . $this->escape('只查得到记录过风险事件的用户') : '';
        if (!$users->count()) return $this->view('未找到：' . $this->code($query) . $note, []);
        $lines = [];
        $buttons = [];
        foreach ($users->values() as $i => $user) {
            $lines[] = ($i + 1) . '\\. ' . $this->code($user->email) . ' · uid ' . $this->code($user->id) .
                ($this->isolated($user) ? ' · 🔒 已隔离' : '');
            $buttons[] = [$this->button(($i + 1) . '. ' . $this->shorten($user->email, 40), "r:c:{$user->id}")];
        }
        $text = '🔎 *查询* ' . $this->code($query) . "\n共 {$users->count()} 个用户" . $note . "\n\n" . implode("\n", $lines);
        return $this->view($text, $buttons);
    }

    /**
     * Buttons under an alert about a user. A public IP that is not allowlisted can be added to the IP list (unless it
     * is listed already) or allowlisted, on its own row so as not to be taken for the other.
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
            $risk = new RiskService();
            $allowable = $risk->allowRangeFor((string)$event->ip) !== null && !$risk->allowEntryFor((string)$event->ip);
            $second = [];
            if ($allowable && $this->canListIp($event->ip)) $second[] = $this->button('➕ IP 加入名单', "r:p:{$event->id}");
            $second[] = $this->button('✅ 已处理', "r:k:{$event->id}");
            $rows[] = $second;
            if ($allowable) $rows[] = [$this->button('🟢 放行此 IP（白名单）', "r:w:{$event->id}")];
        }
        return $rows;
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

    private function eventLines(User $user, string $type, int $limit): string
    {
        $events = RiskEvent::where('user_id', $user->id)->where('event_type', $type)
            ->orderByDesc('last_seen_at')->orderByDesc('id')->limit($limit)->get();
        return $events->count() ? $events->map(function (RiskEvent $event) { return $this->eventLine($event); })->implode("\n") : '无记录';
    }

    private function eventLine(RiskEvent $event): string
    {
        $ua = preg_replace('/\s+/', ' ', (string)$event->user_agent);
        return $this->code($this->time($event->last_seen_at, 'm-d H:i:s')) . ' \\| ' . $this->code($event->ip) . ' \\| ' .
            $this->code($this->shorten($ua, 60)) . ' \\| x' . (int)$event->occurrences;
    }

    private function canListIp($ip): bool
    {
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) return false;
        $values = array_unique([$ip, (new RiskService())->normalizeIndicatorValue('ip', $ip)]);
        return !RiskIndicator::where('type', 'ip')->whereIn('value', $values)->where('enabled', 1)->exists();
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
