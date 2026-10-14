<?php

namespace App\Plugins\RiskTelegram\Commands;

use App\Models\User;
use App\Plugins\RiskTelegram\RiskBot;

class Health extends RiskCommand
{
    public $command = '/health';
    public $description = '风控状态';
    public $sort = 130;

    public function handle(RiskBot $bot, $message, ?User $admin): void
    {
        $bot->replyView($message, $bot->view()->health());
    }
}
