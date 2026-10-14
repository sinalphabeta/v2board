<?php

namespace App\Plugins\RiskTelegram\Commands;

use App\Models\User;
use App\Plugins\RiskTelegram\RiskBot;

class Id extends RiskCommand
{
    public $command = '/id';
    public $description = '显示我的 Telegram ID';
    public $sort = 150;
    public $public = true;

    public function handle(RiskBot $bot, $message, ?User $admin): void
    {
        $bot->reply($message, (string)$message->sender_id);
    }
}
