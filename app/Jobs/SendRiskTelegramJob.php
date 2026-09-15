<?php

namespace App\Jobs;

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

    public $tries = 3;
    public $timeout = 10;

    public function __construct(int $telegramId, string $text, ?string $ip = null)
    {
        $this->onQueue('send_telegram');
        $this->telegramId = $telegramId;
        $this->text = $text;
        $this->ip = $ip;
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
                $infoLine = "\nip_info: " . $this->markdownCode($ipInfoService->describe($this->ip));
                $text = substr_replace($text, $ipLine . $infoLine, $position, strlen($ipLine));
            }
        }
        (new TelegramService($token))->sendMessage($this->telegramId, $text, 'MarkdownV2');
    }

    private function markdownCode($value): string
    {
        return '`' . str_replace(['\\', '`'], ['\\\\', '\\`'], (string)$value) . '`';
    }
}
