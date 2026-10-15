<?php

namespace App\Plugins\RiskTelegram\Commands;

use App\Models\User;
use App\Plugins\RiskTelegram\RiskBot;

class Id extends RiskCommand
{
    public $command = '/id';
    public $description = '显示我的 Telegram ID，在群里还显示群的 Chat ID';
    public $sort = 150;
    public $public = true;

    public function handle(RiskBot $bot, $message, ?User $admin): void
    {
        if ($message->is_private) {
            $bot->reply($message, (string)$message->sender_id);
            return;
        }
        // In a group, also the group's ID: what the 告警群 Chat ID setting needs
        $view = $bot->view();
        $bot->reply($message, $view->escape('你的 Telegram ID：') . $view->code($message->sender_id) . "\n"
            . $view->escape('本群 Chat ID：') . $view->code($message->chat_id), true);
    }
}
