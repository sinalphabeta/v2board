<?php

namespace App\Plugins\RiskTelegram\Commands;

use App\Models\User;
use App\Plugins\RiskTelegram\RiskBot;

class RiskUsers extends RiskCommand
{
    public $command = '/riskusers';
    public $description = '已隔离的用户';
    public $sort = 50;

    public function handle(RiskBot $bot, $message, ?User $admin): void
    {
        $bot->replyView($message, $bot->view()->riskUsers((int)($message->args[0] ?? 1)));
    }
}
