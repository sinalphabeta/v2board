<?php

namespace App\Plugins\RiskTelegram\Commands;

use App\Models\RiskIndicator;
use App\Plugins\RiskTelegram\RiskBot;
use App\Plugins\RiskTelegram\RiskOperator;
use App\Plugins\RiskTelegram\RiskView;
use App\Services\RiskService;

class Edit extends RiskCommand
{
    public $command = '/edit';
    public $description = '修改名单备注：/edit 值或ID 备注';
    public $sort = 110;

    public function handle(RiskBot $bot, $message, ?RiskOperator $operator): void
    {
        $view = $bot->view();
        $target = (string)($message->args[0] ?? '');
        if ($target === '') {
            $bot->reply($message, '用法: ' . $view->code('/edit 值或ID 备注') . "\n" . $view->escape('不写备注就是清空备注'), true);
            return;
        }
        $note = trim(implode(' ', array_slice($message->args, 1)));
        if (mb_strlen($note, 'UTF-8') > 255) {
            $bot->reply($message, '备注太长，最多 255 个字');
            return;
        }
        $service = $operator->service();
        $indicators = ctype_digit($target) ? RiskIndicator::where('id', (int)$target)->get() : $this->findByValue($service, $target);
        if ($indicators->isEmpty()) {
            $bot->reply($message, '未找到：' . $view->code($target), true);
            return;
        }
        // An allowlisted IP is often also a disabled IP indicator: then the enabled one is meant
        $enabled = $indicators->filter(function (RiskIndicator $indicator) { return $indicator->enabled; });
        if ($indicators->count() > 1 && $enabled->count() === 1) $indicators = $enabled;
        if ($indicators->count() > 1) {
            $bot->reply($message, "这个值在多份名单里，请用 ID：\n" . $indicators->map(function (RiskIndicator $indicator) use ($view) {
                return '• ID ' . $view->code($indicator->id) . ' · ' . RiskView::TYPES[$indicator->type] . ' ' . $view->code($indicator->value) .
                    ($indicator->enabled ? '' : '（已停用）');
            })->implode("\n"), true);
            return;
        }
        $indicator = $indicators->first();
        $service->updateIndicator($indicator, ['note' => $note === '' ? null : $note]);
        $bot->reply($message, '✅ 已更新备注：' . RiskView::TYPES[$indicator->type] . ' ' . $view->code($indicator->value), true);
    }

    private function findByValue(RiskService $service, string $target)
    {
        $values = [trim($target)];
        foreach (array_keys(RiskView::TYPES) as $type) $values[] = $service->normalizeIndicatorValue($type, $target);
        return RiskIndicator::whereIn('value', array_values(array_unique(array_filter($values))))->orderBy('id')->get();
    }
}
