<?php

namespace App\Plugins\RiskTelegram\Commands;

use App\Plugins\RiskTelegram\RiskBot;
use App\Plugins\RiskTelegram\RiskOperator;

class Menu extends RiskCommand
{
    public $command = '/menu';
    public $description = '打开风控菜单';
    public $sort = 10;
    public $aliases = ['/start'];

    public function handle(RiskBot $bot, $message, ?RiskOperator $operator): void
    {
        $bot->replyView($message, $bot->view()->menu());
    }
}
