<?php
namespace App\Plugins\Telegram\Commands;
use App\Models\RiskIndicator;
class ListIp extends RiskCommand
{
    public $command = '/listip';
    public $description = '分页查看 IP 风险名单';
    public function handle($message, $match = []) { if (!$this->authorized($message)) return; $this->sendIndicatorPage('ip', 'IP 风险名单', 'risk_ip', (int)($message->args[0] ?? 1), (int)$message->chat_id); }
    public function handleCallback($message, string $callbackQueryId, int $page) { if (!$this->authorized($message)) { $this->telegramService->answerCallbackQuery($callbackQueryId, '无权限'); return; } $this->telegramService->answerCallbackQuery($callbackQueryId); $this->sendIndicatorPage('ip', 'IP 风险名单', 'risk_ip', $page, (int)$message->chat_id, (int)$message->message_id); }
}
