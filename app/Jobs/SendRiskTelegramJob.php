<?php

namespace App\Jobs;

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

    public $tries = 3;
    public $timeout = 10;

    public function __construct(int $telegramId, string $text)
    {
        $this->onQueue('send_telegram');
        $this->telegramId = $telegramId;
        $this->text = $text;
    }

    public function handle()
    {
        $token = (string)config('risk.bot_token', '');
        if (!$token) return;
        (new TelegramService($token))->sendMessage($this->telegramId, $this->text, 'MarkdownV2');
    }
}
