<?php

namespace App\Plugins\RiskTelegram\Commands;

use App\Plugins\RiskTelegram\RiskBot;
use App\Plugins\RiskTelegram\RiskOperator;

class RiskUsers extends RiskCommand
{
    public $command = '/riskusers';
    public $description = '已隔离的用户';
    public $sort = 50;

    public function handle(RiskBot $bot, $message, ?RiskOperator $operator): void
    {
        $bot->replyView($message, $bot->view()->riskUsers((int)($message->args[0] ?? 1)));
    }
}
