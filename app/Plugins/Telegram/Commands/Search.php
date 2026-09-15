<?php

namespace App\Plugins\Telegram\Commands;

use App\Models\Plan;
use App\Models\User;
use App\Services\RiskService;

class Search extends RiskCommand
{
    public $command = '/search';
    public $description = '查询风险用户详情和访问记录';

    public function handle($message, $match = [])
    {
        if (!$this->authorized($message)) return;
        $email = (new RiskService())->normalizeEmail($message->args[0] ?? '');
        if ($email === '') {
            $this->telegramService->sendMessage($message->chat_id, '用法：/search email@example.com');
            return;
        }
        $user = User::whereRaw('LOWER(TRIM(email)) = ?', [$email])->where('risk_status', 1)->first();
        if (!$user) {
            $this->telegramService->sendMessage($message->chat_id, '未找到已标记的内鬼用户');
            return;
        }
        $plan = $user->plan_id ? Plan::find($user->plan_id) : null;
        $text = "🔎 内鬼用户详情\n" . $this->userSummary($user, $plan) .
            "\n\n最近 10 次拉取订阅（时间 | IP | UA | 次数）\n" .
            $this->eventLines($user, 'subscription') .
            "\n\n最近 10 次登录（时间 | IP | UA | 次数）\n" .
            $this->eventLines($user, 'login');
        $this->telegramService->sendMessage($message->chat_id, $text);
    }
}
