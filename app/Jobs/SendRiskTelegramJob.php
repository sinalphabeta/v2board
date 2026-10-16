<?php

namespace App\Jobs;

use App\Models\RiskEvent;
use App\Models\User;
use App\Plugins\RiskTelegram\RiskView;
use App\Services\IpInfoService;
use App\Services\RiskAlertService;
use App\Services\RiskSettings;
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
    // The alert's subject (RiskAlertService) on the day it was let through; $remind: a reminder, sent as a reply to
    // that day's first alert of the subject
    protected $subject;
    protected $day;
    protected $remind;

    // Waiting for a sending slot or after Telegram's 429 is not a failure: retried for an hour, failed after 3 errors
    public $maxExceptions = 3;
    // A real error (Telegram unreachable): tried 3 times within about 20 seconds; a 429 waits as Telegram asks instead
    public $backoff = [5, 15];
    public $timeout = 10;

    public function __construct(int $telegramId, string $text, ?string $ip = null, ?int $userId = null, ?int $eventId = null,
                                ?string $subject = null, bool $remind = false)
    {
        $this->onQueue('send_telegram');
        $this->telegramId = $telegramId;
        $this->text = $text;
        $this->ip = $ip;
        $this->userId = $userId;
        $this->eventId = $eventId;
        $this->subject = $subject;
        $this->day = date('Ymd');
        $this->remind = $remind;
    }

    public function retryUntil()
    {
        return now()->addHour();
    }

    public function handle(IpInfoService $ipInfoService)
    {
        $token = (string)RiskSettings::get('bot_token');
        if (!$token) return;
        $alerts = new RiskAlertService();
        $wait = $alerts->slot();
        if ($wait) {
            $this->release($wait);
            return;
        }
        $text = $this->text;
        if (RiskSettings::get('ip_info_enabled') && filter_var($this->ip, FILTER_VALIDATE_IP)) {
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
        $first = $this->remind && $this->subject ? $alerts->first($this->subject, (string)$this->day) : null;
        $replyTo = $first && $first['message'] ? (int)$first['message']['message_id'] : null;
        try {
            $response = app()->makeWith(TelegramService::class, ['token' => $token])
                ->sendMessage($this->telegramId, $text, 'MarkdownV2', $keyboard, $replyTo);
        } catch (\Throwable $e) {
            $wait = RiskAlertService::retryAfter($e);
            if ($wait === null) throw $e;
            $this->release($wait);
            return;
        }
        $messageId = (int)($response->result->message_id ?? 0);
        if ($this->subject && $messageId) {
            $alerts->sent($this->subject, (string)$this->day, $this->telegramId, $messageId, $text, !$this->remind);
        }
    }

    private function markdownCode($value): string
    {
        return '`' . str_replace(['\\', '`'], ['\\\\', '\\`'], (string)$value) . '`';
    }
}
