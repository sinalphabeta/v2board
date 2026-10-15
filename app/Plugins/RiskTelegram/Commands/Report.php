<?php

namespace App\Plugins\RiskTelegram\Commands;

use App\Models\User;
use App\Plugins\RiskTelegram\RiskBot;
use App\Services\RiskService;

class Report extends RiskCommand
{
    public $command = '/report';
    public $description = '今日概况：访问、告警和要留意的用户';
    public $sort = 125;

    public function handle(RiskBot $bot, $message, ?User $admin): void
    {
        $bot->replyView($message, $bot->view()->report((new RiskService())->links()->reportToday(), false));
    }
}
