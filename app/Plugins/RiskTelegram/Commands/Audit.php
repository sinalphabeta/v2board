<?php

namespace App\Plugins\RiskTelegram\Commands;

use App\Plugins\RiskTelegram\RiskBot;
use App\Plugins\RiskTelegram\RiskOperator;

class Audit extends RiskCommand
{
    public $command = '/audit';
    public $description = '操作记录';
    public $sort = 120;

    public function handle(RiskBot $bot, $message, ?RiskOperator $operator): void
    {
        $bot->replyView($message, $bot->view()->audit((int)($message->args[0] ?? 1)));
    }
}
