<?php

namespace App\Plugins\RiskTelegram\Commands;

use App\Plugins\RiskTelegram\RiskBot;
use App\Plugins\RiskTelegram\RiskOperator;
use App\Services\RiskService;

/**
 * /add, /del and /list for one type of indicator.
 */
abstract class IndicatorCommand extends RiskCommand
{
    protected $type;
    // add, del or list
    protected $action;
    protected $usage;

    public function handle(RiskBot $bot, $message, ?RiskOperator $operator): void
    {
        if ($this->action === 'list') {
            $bot->replyView($message, $bot->view()->indicators($this->type, (int)($message->args[0] ?? 1)));
            return;
        }
        $values = $this->type === 'ua' ? array_filter([implode(' ', $message->args)]) : $message->args;
        // Without arguments, a reply to an alert or a user card takes the email or IP from it
        if (!$values && in_array($this->type, ['email', 'ip', 'allow_ip', 'node_ip'], true)) {
            $value = $bot->replyField($message, $this->type === 'email' ? 'email' : 'ip');
            // An alert's IPv6 address is allowlisted as its /64, as by the alert's button
            if ($value !== null && in_array($this->type, RiskService::ALLOW_TYPES, true)) $value = (new RiskService())->allowRangeFor($value) ?? $value;
            $values = array_filter([$value]);
        }
        if (!$values) {
            $bot->reply($message, '用法: ' . $bot->view()->code($this->command . ' ' . $this->usage), true);
            return;
        }
        if ($this->action === 'add') $bot->addIndicators($message, $operator, $this->type, $values);
        else $bot->removeIndicators($message, $operator, $this->type, $values);
    }
}
