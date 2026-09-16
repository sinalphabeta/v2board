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
            $this->sendReply($message, '请私聊风险 Bot 执行此命令');
            return false;
        }
        $telegramId = $message->sender_id ?? $message->chat_id;
        $user = User::where('telegram_id', $telegramId)->where('is_admin', 1)->first();
        if (!$user) { $this->sendReply($message, '无权限'); return false; }
        $this->actorId = $user->id;
        return true;
    }

    protected function add($message, string $type): void
    {
        if (!$this->authorized($message)) return;
        if (empty($message->args[0])) { $this->sendMarkdownReply($message, '用法: `' . $this->command . ' value`'); return; }

        $service = new RiskService();
        $values = $type === 'ua' ? [implode(' ', $message->args)] : $message->args;
        $added = [];
        $existing = [];
        $invalid = [];
        foreach ($values as $rawValue) {
            if ($type === 'email') $value = $service->normalizeEmail($rawValue);
            elseif ($type === 'asn') $value = $service->normalizeAsn($rawValue) ?: trim((string)$rawValue);
            else $value = trim((string)$rawValue);
            if (!$this->validIndicatorValue($type, $value)) {
                $invalid[] = $value;
                continue;
            }
            $indicator = RiskIndicator::where('type', $type)->where('value', $value)->first();
            if ($indicator && (int)$indicator->enabled === 1) {
                $existing[] = $value;
                continue;
            }
            $service->addIndicator($type, $value, null, $this->actorId);
            $added[] = $value;
        }
        $text = '*操作完成*';
        if ($added) $text .= "\n\n✅ 新增 " . count($added) . " 条:\n" . $this->bulletList($added);
        if ($existing) $text .= "\n\n⚠️ 已存在 " . count($existing) . " 条:\n" . $this->bulletList($existing);
        if ($invalid) $text .= "\n\n❌ 格式无效 " . count($invalid) . " 条:\n" . $this->bulletList($invalid);
        $this->sendMarkdownReply($message, $text);
    }

    protected function userSummary(User $user, ?Plan $plan = null): string
    {
        $used = ((int)$user->u + (int)$user->d) / 1073741824;
        $total = (int)$user->transfer_enable / 1073741824;
        $traffic = $this->escapeMarkdown(number_format($used, 2) . ' / ' . number_format($total, 2) . ' GB');
        $expired = $user->expired_at === null ? '长期有效' : date('Y-m-d H:i:s', (int)$user->expired_at);
        $registered = $user->created_at ? date('Y-m-d H:i:s', (int)$user->created_at) : '-';
        return "邮箱: " . $this->markdownCode($user->email) . "\nuid: " . $this->markdownCode((int)$user->id) . "\n注册时间: " .
            $this->escapeMarkdown($registered) . "\n套餐: " . $this->escapeMarkdown($plan ? $plan->name : '无订阅') .
            "\n流量: " . $traffic . "\n到期时间: " .
            $this->escapeMarkdown($expired) . "\n权限组: " . $this->escapeMarkdown($user->group_id ?? '-');
    }

    protected function delete($message, string $type): void
    {
        if (!$this->authorized($message)) return;
        if (empty($message->args[0])) { $this->sendMarkdownReply($message, '用法: `' . $this->command . ' value`'); return; }

        $service = new RiskService();
        $values = $type === 'ua' ? [implode(' ', $message->args)] : $message->args;
        $deleted = [];
        $missing = [];
        foreach ($values as $rawValue) {
            if ($type === 'email') $value = $service->normalizeEmail($rawValue);
            elseif ($type === 'asn') $value = $service->normalizeAsn($rawValue) ?: trim((string)$rawValue);
            else $value = trim((string)$rawValue);
            $indicator = RiskIndicator::where('type', $type)->where('value', $value)->where('enabled', 1)->first();
            if (!$indicator) {
                $missing[] = $value;
                continue;
            }
            if ($service->removeIndicator($indicator, $this->actorId)) $deleted[] = $value;
        }
        $text = '*操作完成*';
        if ($deleted) $text .= "\n\n✅ 删除 " . count($deleted) . " 条:\n" . $this->bulletList($deleted);
        if ($missing) $text .= "\n\n⚠️ 不存在 " . count($missing) . " 条:\n" . $this->bulletList($missing);
        $this->sendMarkdownReply($message, $text);
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
            return $this->markdownCode($time) . ' \\| ' . $this->markdownCode($event->ip) . ' \\| ' .
                $this->markdownCode(substr($ua, 0, 96)) . " \\| x" . (int)$event->occurrences;
        })->implode("\n");
    }

    protected function sendIndicatorPage(string $type, string $title, string $callbackPrefix, int $page, int $chatId, int $messageId = 0, int $replyToMessageId = 0): void
    {
        $pageSize = $type === 'ua' ? 10 : 20;
        $query = RiskIndicator::where('type', $type)->where('enabled', 1)->orderBy('value', 'asc');
        $total = $query->count();
        $pages = max(1, (int)ceil($total / $pageSize));
        $page = min(max(1, $page), $pages);
        $values = $query->forPage($page, $pageSize)->pluck('value');
        $text = "📋 *" . $this->escapeMarkdown($title) . "*\n共 {$total} 条\n第 {$page}/{$pages} 页";
        $text .= $values->count() ? "\n\n" . $this->bulletList($values->all()) : "\n\nempty";
        $buttons = [];
        if ($page > 1) $buttons[] = ['text' => '⬅️ 上一页', 'callback_data' => $callbackPrefix . ':' . ($page - 1)];
        if ($page < $pages) $buttons[] = ['text' => '下一页 ➡️', 'callback_data' => $callbackPrefix . ':' . ($page + 1)];
        $markup = ['inline_keyboard' => $buttons ? [$buttons] : []];
        if ($messageId) $this->telegramService->editMessageText($chatId, $messageId, $text, 'MarkdownV2', $markup);
        else $this->telegramService->sendMessage($chatId, $text, 'MarkdownV2', $markup, $replyToMessageId ?: null);
    }

    protected function sendMarkdown(int $chatId, string $text, array $replyMarkup = []): void
    {
        $this->telegramService->sendMessage($chatId, $text, 'MarkdownV2', $replyMarkup);
    }

    protected function sendReply($message, string $text, string $parseMode = '', array $replyMarkup = []): void
    {
        $replyToMessageId = !empty($message->message_id) ? (int)$message->message_id : null;
        $this->telegramService->sendMessage((int)$message->chat_id, $text, $parseMode, $replyMarkup, $replyToMessageId);
    }

    protected function sendMarkdownReply($message, string $text, array $replyMarkup = []): void
    {
        $this->sendReply($message, $text, 'MarkdownV2', $replyMarkup);
    }

    protected function escapeMarkdown($value): string
    {
        return preg_replace_callback('/[_*\[\]()~`>#+\-=|{}.!\\\\]/', function ($match) {
            return '\\' . $match[0];
        }, (string)$value);
    }

    protected function bulletList(array $values): string
    {
        return implode("\n", array_map(function ($value) {
            return '• ' . $this->markdownCode($value);
        }, $values));
    }

    protected function numberedItem(int $number, string $content): string
    {
        return $number . '\\. ' . $content;
    }

    protected function markdownCode($value): string
    {
        return '`' . str_replace(['\\', '`'], ['\\\\', '\\`'], (string)$value) . '`';
    }

    private function validIndicatorValue(string $type, string $value): bool
    {
        if ($value === '' || strlen($value) > 255) return false;
        if ($type === 'email') return (bool)filter_var($value, FILTER_VALIDATE_EMAIL);
        if ($type === 'asn') return (new RiskService())->normalizeAsn($value) !== null;
        if ($type !== 'ip') return true;
        [$address, $bits] = array_pad(explode('/', $value, 2), 2, null);
        if (!filter_var($address, FILTER_VALIDATE_IP)) return false;
        if ($bits === null) return true;
        $max = filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) ? 128 : 32;
        return ctype_digit($bits) && (int)$bits <= $max;
    }
}
