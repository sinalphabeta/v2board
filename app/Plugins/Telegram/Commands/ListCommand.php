<?php
namespace App\Plugins\Telegram\Commands;
use App\Models\RiskIndicator;
class ListCommand extends RiskCommand
{
    public $command = '/list';
    public $description = '分页查看邮箱风险名单';
    public const PAGE_SIZE = 20;

    public function handle($message, $match = [])
    {
        if (!$this->authorized($message)) return;
        $this->sendPage((int)($message->args[0] ?? 1), (int)$message->chat_id);
    }

    public function handleCallback($message, string $callbackQueryId, int $page)
    {
        if (!$this->authorized($message)) {
            $this->telegramService->answerCallbackQuery($callbackQueryId, '无权限');
            return;
        }
        $page = max(1, $page);
        $this->telegramService->answerCallbackQuery($callbackQueryId);
        $this->sendPage($page, (int)$message->chat_id, (int)$message->message_id);
    }

    private function sendPage(int $page, int $chatId, int $messageId = 0): void
    {
        $total = RiskIndicator::where('type', 'email')->where('enabled', 1)->count();
        $pages = max(1, (int)ceil($total / self::PAGE_SIZE));
        $page = min(max(1, $page), $pages);
        $emails = RiskIndicator::where('type', 'email')
            ->where('enabled', 1)
            ->orderBy('value', 'asc')
            ->forPage($page, self::PAGE_SIZE)
            ->pluck('value');
        $text = "📋 内鬼邮箱 共 {$total} 条 第 {$page}/{$pages} 页";
        if ($emails->count()) $text .= "\n\n" . $emails->implode("\n");
        else $text .= "\n\nempty";
        $buttons = [];
        if ($page > 1) $buttons[] = ['text' => '⬅️ 上一页', 'callback_data' => 'risk_list:' . ($page - 1)];
        if ($page < $pages) $buttons[] = ['text' => '下一页 ➡️', 'callback_data' => 'risk_list:' . ($page + 1)];
        $markup = ['inline_keyboard' => $buttons ? [$buttons] : []];
        if ($messageId) $this->telegramService->editMessageText($chatId, $messageId, $text, '', $markup);
        else $this->telegramService->sendMessage($chatId, $text, '', $markup);
    }
}
