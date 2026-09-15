<?php
namespace App\Plugins\Telegram\Commands;
use App\Models\RiskIndicator;
class ListUa extends RiskCommand
{
    public $command = '/listua';
    public $description = '分页查看 UA 风险名单';
    public function handle($message, $match = []) { if (!$this->authorized($message)) return; $this->sendIndicatorPage('ua', 'UA 风险名单', 'risk_ua', (int)($message->args[0] ?? 1), (int)$message->chat_id, 0, (int)($message->message_id ?? 0)); }
    public function handleCallback($message, string $callbackQueryId, int $page) { if (!$this->authorized($message)) { $this->telegramService->answerCallbackQuery($callbackQueryId, '无权限'); return; } $this->telegramService->answerCallbackQuery($callbackQueryId); $this->sendIndicatorPage('ua', 'UA 风险名单', 'risk_ua', $page, (int)$message->chat_id, (int)$message->message_id); }
}
