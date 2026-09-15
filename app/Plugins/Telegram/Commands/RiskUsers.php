<?php

namespace App\Plugins\Telegram\Commands;

use App\Models\Plan;
use App\Models\User;

class RiskUsers extends RiskCommand
{
    public $command = '/riskusers';
    public $description = '分页查看已标记风险用户';
    public const PAGE_SIZE = 5;

    public function handle($message, $match = [])
    {
        if (!$this->authorized($message)) return;
        $this->sendPage((int)($message->args[0] ?? 1), (int)$message->chat_id, 0, (int)($message->message_id ?? 0));
    }

    public function handleCallback($message, string $callbackQueryId, int $page)
    {
        if (!$this->authorized($message)) {
            $this->telegramService->answerCallbackQuery($callbackQueryId, '无权限');
            return;
        }
        $this->telegramService->answerCallbackQuery($callbackQueryId);
        $this->sendPage($page, (int)$message->chat_id, (int)$message->message_id);
    }

    private function sendPage(int $page, int $chatId, int $messageId = 0, int $replyToMessageId = 0): void
    {
        $query = User::where('risk_status', 1)->orderBy('id', 'asc');
        $total = $query->count();
        $pages = max(1, (int)ceil($total / self::PAGE_SIZE));
        $page = min(max(1, $page), $pages);
        $users = $query->forPage($page, self::PAGE_SIZE)->get();
        $plans = Plan::whereIn('id', $users->pluck('plan_id')->filter()->all())->get()->keyBy('id');
        $text = "📋 *内鬼用户*\n共 {$total} 个\n第 {$page}/{$pages} 页";
        foreach ($users as $index => $user) {
            $number = ($page - 1) * self::PAGE_SIZE + $index + 1;
            $text .= "\n\n" . $this->numberedItem($number, $this->userSummary($user, $plans->get($user->plan_id)));
        }
        if (!$users->count()) $text .= "\n\nempty";
        $buttons = [];
        if ($page > 1) $buttons[] = ['text' => '⬅️ 上一页', 'callback_data' => 'risk_users:' . ($page - 1)];
        if ($page < $pages) $buttons[] = ['text' => '下一页 ➡️', 'callback_data' => 'risk_users:' . ($page + 1)];
        $markup = ['inline_keyboard' => $buttons ? [$buttons] : []];
        if ($messageId) $this->telegramService->editMessageText($chatId, $messageId, $text, 'MarkdownV2', $markup);
        else $this->telegramService->sendMessage($chatId, $text, 'MarkdownV2', $markup, $replyToMessageId ?: null);
    }
}
