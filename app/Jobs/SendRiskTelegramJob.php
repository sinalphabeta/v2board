<?php

namespace App\Jobs;

use App\Models\RiskEvent;
use App\Models\User;
use App\Plugins\RiskTelegram\RiskView;
use App\Services\IpInfoService;
use App\Services\TelegramService;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;

class SendRiskTelegramJob implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    protected $telegramId;
    protected $text;
    protected $ip;
    // The user and event the alert is about, for its buttons (jobs queued by older code have neither)
    protected $userId;
    protected $eventId;

    public $tries = 3;
    public $timeout = 10;

    public function __construct(int $telegramId, string $text, ?string $ip = null, ?int $userId = null, ?int $eventId = null)
    {
        $this->onQueue('send_telegram');
        $this->telegramId = $telegramId;
        $this->text = $text;
        $this->ip = $ip;
        $this->userId = $userId;
        $this->eventId = $eventId;
    }

    public function handle(IpInfoService $ipInfoService)
    {
        $token = (string)config('risk.bot_token', '');
        if (!$token) return;
        $text = $this->text;
        if (config('risk.ip_info_enabled', true) && filter_var($this->ip, FILTER_VALIDATE_IP)) {
            $ipLine = "\nip: " . $this->markdownCode($this->ip);
            $position = strpos($text, $ipLine);
            if ($position !== false) {
                $result = $ipInfoService->lookup($this->ip);
                $infoLines = "\nip\\_info: " . $this->markdownCode($result['ip_info']);
                if ($result['asn'] !== null) {
                    $infoLines .= "\nasn: " . $this->markdownCode($result['asn']);
                }
                $text = substr_replace($text, $ipLine . $infoLines, $position, strlen($ipLine));
            }
        }
        // Buttons follow the user's state when the alert is sent, e.g. 解除隔离 for an isolated user
        $user = $this->userId ? User::find($this->userId) : null;
        $event = $user && $this->eventId ? RiskEvent::find($this->eventId) : null;
        $keyboard = $user ? ['inline_keyboard' => (new RiskView())->alertKeyboard($user, $event)] : [];
        app()->makeWith(TelegramService::class, ['token' => $token])->sendMessage($this->telegramId, $text, 'MarkdownV2', $keyboard);
    }

    private function markdownCode($value): string
    {
        return '`' . str_replace(['\\', '`'], ['\\\\', '\\`'], (string)$value) . '`';
    }
}
