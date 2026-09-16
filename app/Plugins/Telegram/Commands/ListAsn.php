<?php
namespace App\Plugins\Telegram\Commands;
use App\Models\RiskIndicator;
class ListAsn extends RiskCommand
{
    public $command = '/listasn';
    public $description = '分页查看 ASN 风险名单';
    public function handle($message, $match = []) { if (!$this->authorized($message)) return; $this->sendIndicatorPage('asn', 'ASN 风险名单', 'risk_asn', (int)($message->args[0] ?? 1), (int)$message->chat_id, 0, (int)($message->message_id ?? 0)); }
    public function handleCallback($message, string $callbackQueryId, int $page) { if (!$this->authorized($message)) { $this->telegramService->answerCallbackQuery($callbackQueryId, '无权限'); return; } $this->telegramService->answerCallbackQuery($callbackQueryId); $this->sendIndicatorPage('asn', 'ASN 风险名单', 'risk_asn', $page, (int)$message->chat_id, (int)$message->message_id); }
}
