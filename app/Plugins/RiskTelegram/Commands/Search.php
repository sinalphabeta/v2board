<?php

namespace App\Plugins\RiskTelegram\Commands;

use App\Plugins\RiskTelegram\RiskBot;
use App\Plugins\RiskTelegram\RiskOperator;
use App\Services\RiskService;

class Search extends RiskCommand
{
    public $command = '/search';
    public $description = '查询用户：邮箱、uid 或 IP';
    public $sort = 20;
    public $aliases = ['/find'];

    public function handle(RiskBot $bot, $message, ?RiskOperator $operator): void
    {
        $query = trim(implode(' ', $message->args));
        // Without arguments, a reply to an alert or a user card searches for its user
        if ($query === '') {
            $query = (string)($bot->replyField($message, 'uid') ?? $bot->replyField($message, 'email') ?? $bot->replyField($message, 'ip'));
        }
        if ($query === '') {
            $bot->reply($message, '用法: /search 邮箱、uid 或 IP（也可以回复一条告警或用户卡片）');
            return;
        }
        $service = new RiskService();
        $users = $service->findUsers($query);
        if ($users->count() === 1) {
            $bot->replyView($message, $bot->view()->userCard($users->first()));
            return;
        }
        // For an IP, what each of its users did from it
        $usage = filter_var($query, FILTER_VALIDATE_IP) ? ($service->ipUsage([$query], $service->searchDays())[$query] ?? []) : [];
        $bot->replyView($message, $bot->view()->searchResults($users, $query, $usage));
    }
}
