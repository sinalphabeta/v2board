<?php

namespace App\Console\Commands;

use App\Plugins\RiskTelegram\RiskView;
use App\Services\RiskService;
use App\Services\RiskSettings;
use App\Services\TelegramService;
use Illuminate\Console\Command;

class RiskSummary extends Command
{
    protected $signature = 'risk:summary';
    protected $description = "Send yesterday's risk report to the alert chat (the daily report)";

    public function handle()
    {
        $token = (string)RiskSettings::get('bot_token');
        $chatId = (string)RiskSettings::get('alert_chat_id');
        if (!RiskSettings::get('daily_report') || !$token || !$chatId) return;
        $risk = new RiskService();
        $to = $risk->access()->day(time());
        $view = (new RiskView())->report($risk->links()->report(strtotime('yesterday', $to), $to), false);
        app()->makeWith(TelegramService::class, ['token' => $token])
            ->sendMessage((int)$chatId, $view['text'], 'MarkdownV2', $view['keyboard'] ? ['inline_keyboard' => $view['keyboard']] : []);
        $this->info('Daily report sent');
    }
}
