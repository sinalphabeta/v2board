<?php

namespace App\Plugins\RiskTelegram\Commands;

use App\Plugins\RiskTelegram\RiskBot;
use App\Plugins\RiskTelegram\RiskOperator;

class Events extends RiskCommand
{
    public $command = '/events';
    public $description = '最近的风险事件';
    public $sort = 60;

    public function handle(RiskBot $bot, $message, ?RiskOperator $operator): void
    {
        $bot->replyView($message, $bot->view()->events((int)($message->args[0] ?? 1)));
    }
}
