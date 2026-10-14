<?php

namespace App\Plugins\RiskTelegram\Commands;

use App\Models\User;
use App\Plugins\RiskTelegram\RiskBot;

abstract class RiskCommand
{
    public $command;
    public $description;
    // Position in the Telegram command menu
    public $sort = 100;
    // Other names that run the command but are not listed in the menu
    public $aliases = [];
    // Whether anyone may run it; the other commands need an admin with a bound Telegram account
    public $public = false;

    /**
     * $message: command, args, chat_id, message_id, is_private, sender_id and reply_text (the risk bot's message it
     * replies to). $admin is null only for public commands.
     */
    abstract public function handle(RiskBot $bot, $message, ?User $admin): void;
}
