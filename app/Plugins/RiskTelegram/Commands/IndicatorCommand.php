<?php

namespace App\Plugins\RiskTelegram\Commands;

use App\Models\User;
use App\Plugins\RiskTelegram\RiskBot;

/**
 * /add, /del and /list for one type of indicator.
 */
abstract class IndicatorCommand extends RiskCommand
{
    protected $type;
    // add, del or list
    protected $action;
    protected $usage;

    public function handle(RiskBot $bot, $message, ?User $admin): void
    {
        if ($this->action === 'list') {
            $bot->replyView($message, $bot->view()->indicators($this->type, (int)($message->args[0] ?? 1)));
            return;
        }
        $values = $this->type === 'ua' ? array_filter([implode(' ', $message->args)]) : $message->args;
        // Without arguments, a reply to an alert or a user card takes the email or IP from it
        if (!$values && in_array($this->type, ['email', 'ip'], true)) $values = array_filter([$bot->replyField($message, $this->type)]);
        if (!$values) {
            $bot->reply($message, '用法: ' . $bot->view()->code($this->command . ' ' . $this->usage), true);
            return;
        }
        if ($this->action === 'add') $bot->addIndicators($message, $admin, $this->type, $values);
        else $bot->removeIndicators($message, $admin, $this->type, $values);
    }
}
