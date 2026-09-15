<?php

namespace App\Plugins\Telegram\Commands;

use App\Models\RiskIndicator;
use App\Models\User;
use App\Models\Plan;
use App\Plugins\Telegram\Telegram;
use App\Services\RiskService;
use App\Services\TelegramService;

abstract class RiskCommand extends Telegram
{
    protected $actorId;

    public function __construct()
    {
        $this->telegramService = new TelegramService(config('risk.bot_token', ''));
    }

    protected function authorized($message): bool
    {
        $alertChatId = (string)config('risk.alert_chat_id', '');
        if (empty($message->is_private) && (!$alertChatId || (string)$message->chat_id !== $alertChatId)) {
            $this->telegramService->sendMessage($message->chat_id, '请私聊风险 Bot 执行此命令');
            return false;
        }
        $telegramId = $message->sender_id ?? $message->chat_id;
        $user = User::where('telegram_id', $telegramId)->where('is_admin', 1)->first();
        if (!$user) { $this->telegramService->sendMessage($message->chat_id, '无权限'); return false; }
        $this->actorId = $user->id;
        return true;
    }

    protected function add($message, string $type): void
    {
        if (!$this->authorized($message)) return;
        if (empty($message->args[0])) { $this->telegramService->sendMessage($message->chat_id, '用法：' . $this->command . ' value'); return; }
        (new RiskService())->addIndicator($type, implode(' ', $message->args), null, $this->actorId);
        $this->telegramService->sendMessage($message->chat_id, '已添加');
    }

    protected function userSummary(User $user, ?Plan $plan = null): string
    {
        $used = ((int)$user->u + (int)$user->d) / 1073741824;
        $total = (int)$user->transfer_enable / 1073741824;
        $expired = $user->expired_at === null ? '长期有效' : date('Y-m-d H:i:s', (int)$user->expired_at);
        $registered = $user->created_at ? date('Y-m-d H:i:s', (int)$user->created_at) : '-';
        return "邮箱：{$user->email}\n用户ID：{$user->id}\n注册时间：{$registered}\n套餐：" .
            ($plan ? $plan->name : '无订阅') . "\n流量：" . number_format($used, 2) . '/' .
            number_format($total, 2) . " GB\n到期时间：{$expired}\n权限组：" . ($user->group_id ?? '-');
    }

    protected function eventLines(User $user, string $type): string
    {
        $events = \App\Models\RiskEvent::where('user_id', $user->id)
            ->where('event_type', $type)
            ->orderByDesc('last_seen_at')
            ->limit(10)
            ->get();
        if (!$events->count()) return '无记录';
        return $events->map(function ($event) {
            $time = date('m-d H:i:s', (int)$event->last_seen_at);
            $ua = preg_replace('/\s+/', ' ', (string)$event->user_agent);
            return "{$time} | {$event->ip} | " . substr($ua, 0, 96) . " | x{$event->occurrences}";
        })->implode("\n");
    }

    protected function sendIndicatorPage(string $type, string $title, string $callbackPrefix, int $page, int $chatId, int $messageId = 0): void
    {
        $pageSize = $type === 'ua' ? 10 : 20;
        $query = RiskIndicator::where('type', $type)->where('enabled', 1)->orderBy('value', 'asc');
        $total = $query->count();
        $pages = max(1, (int)ceil($total / $pageSize));
        $page = min(max(1, $page), $pages);
        $values = $query->forPage($page, $pageSize)->pluck('value');
        $text = "📋 {$title} 共 {$total} 条 第 {$page}/{$pages} 页";
        $text .= $values->count() ? "\n\n" . $values->implode("\n") : "\n\nempty";
        $buttons = [];
        if ($page > 1) $buttons[] = ['text' => '⬅️ 上一页', 'callback_data' => $callbackPrefix . ':' . ($page - 1)];
        if ($page < $pages) $buttons[] = ['text' => '下一页 ➡️', 'callback_data' => $callbackPrefix . ':' . ($page + 1)];
        $markup = ['inline_keyboard' => $buttons ? [$buttons] : []];
        if ($messageId) $this->telegramService->editMessageText($chatId, $messageId, $text, '', $markup);
        else $this->telegramService->sendMessage($chatId, $text, '', $markup);
    }
}
