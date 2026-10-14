<?php

namespace App\Plugins\RiskTelegram\Commands;

use App\Models\User;
use App\Plugins\RiskTelegram\RiskBot;

class Help extends RiskCommand
{
    public $command = '/help';
    public $description = '帮助';
    public $sort = 140;

    public function handle(RiskBot $bot, $message, ?User $admin): void
    {
        $bot->replyView($message, $bot->view()->help());
    }
}
