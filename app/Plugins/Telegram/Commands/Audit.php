<?php

namespace App\Plugins\Telegram\Commands;

use App\Models\RiskAudit;

class Audit extends RiskCommand
{
    public $command = '/audit';
    public $description = '查看最近风险操作';
    private const ACTIONS = ['add' => '新增', 'edit' => '编辑', 'delete' => '删除', 'mark' => '隔离用户', 'unmark' => '解除隔离'];
    private const FIELDS = ['value' => '值', 'note' => '备注', 'enabled' => '启用'];
    // Changes that the action itself already says
    private const IMPLIED = ['add' => ['value', 'enabled'], 'delete' => ['enabled']];

    public function handle($message, $match = [])
    {
        if (!$this->authorized($message)) return;
        $rows = RiskAudit::orderByDesc('id')->limit(10)->get();
        if (!$rows->count()) {
            $this->sendReply($message, '暂无记录');
            return;
        }
        $text = '📋 *最近 ' . $rows->count() . ' 条风险操作*';
        foreach ($rows as $row) $text .= "\n\n" . $this->auditLine($row);
        $this->sendMarkdownReply($message, $text);
    }

    private function auditLine(RiskAudit $row): string
    {
        $parts = [
            $this->markdownCode(date('m-d H:i:s', (int)$row->created_at)),
            $this->escapeMarkdown(self::ACTIONS[$row->action] ?? $row->action)
        ];
        if ($row->user_id) $parts[] = 'uid ' . $this->markdownCode((int)$row->user_id);
        $parts[] = $this->escapeMarkdown($row->type) . ' ' . $this->markdownCode($this->shorten($row->value));
        $parts[] = $this->actor($row);
        $line = implode(' \\| ', $parts);

        $changes = [];
        foreach ((array)$row->changes as $field => $change) {
            if (!isset(self::FIELDS[$field]) || in_array($field, self::IMPLIED[$row->action] ?? [], true)) continue;
            $changes[] = self::FIELDS[$field] . ': ' . $this->changeValue($field, $change[0] ?? null) .
                ' → ' . $this->changeValue($field, $change[1] ?? null);
        }
        return $changes ? $line . "\n" . implode('；', $changes) : $line;
    }

    private function actor(RiskAudit $row): string
    {
        if ($row->actor_type === 'bot') return 'Bot uid ' . $this->markdownCode((int)$row->actor_id);
        if ($row->actor_type === 'api') return 'API' . ($row->actor_ip ? ' ' . $this->markdownCode($row->actor_ip) : '');
        if ($row->actor_type === 'system') return '系统';
        return '未知';
    }

    private function changeValue(string $field, $value): string
    {
        if ($value === null || $value === '') return '空';
        if ($field === 'enabled') return $value ? '是' : '否';
        return $this->markdownCode($this->shorten($value));
    }

    private function shorten($value): string
    {
        $value = (string)$value;
        return mb_strlen($value, 'UTF-8') > 60 ? mb_substr($value, 0, 60, 'UTF-8') . '…' : $value;
    }
}
