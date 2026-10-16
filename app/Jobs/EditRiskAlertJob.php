<?php

namespace App\Jobs;

use App\Models\RiskEvent;
use App\Models\User;
use App\Plugins\RiskTelegram\RiskView;
use App\Services\RiskAlertService;
use App\Services\RiskSettings;
use App\Services\TelegramService;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;

/**
 * Update the day's first alert about a subject with what was merged into it since (RiskAlertService): a line at the end,
 * 之后又有 N 条（M 个 IP）· 最后 14:03. Not once its buttons were pressed or the user was isolated.
 */
class EditRiskAlertJob implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    protected $subject;
    protected $day;

    public $maxExceptions = 3;
    // A real error (Telegram unreachable): tried 3 times within about 20 seconds; a 429 waits as Telegram asks instead
    public $backoff = [5, 15];
    public $timeout = 10;

    public function __construct(string $subject, string $day)
    {
        $this->onQueue('send_telegram');
        $this->subject = $subject;
        $this->day = $day;
    }

    public function retryUntil()
    {
        return now()->addHour();
    }

    public function handle()
    {
        $token = (string)RiskSettings::get('bot_token');
        if (!$token) return;
        $alerts = new RiskAlertService();
        $first = $alerts->first($this->subject, $this->day);
        if (!$first || $first['closed']) return;
        if (!$first['message']) {
            // The first alert is still waiting to be sent (or was over the budget, or failed)
            if ($this->attempts() < 5) $this->release(60);
            return;
        }
        [$count, $ips, $last, $users] = $alerts->mergedSince($this->subject, $first['open']);
        if (!$count) return;
        $wait = $alerts->slot();
        if ($wait) {
            $this->release($wait);
            return;
        }
        $view = new RiskView();
        $line = strpos($this->subject, 'register:') === 0
            ? "之后这个 IP 又注册了 {$count} 个账号（uid " . implode('、', array_slice($users, 0, 5)) . (count($users) > 5 ? ' 等' : '') . '）'
            : "之后又有 {$count} 条（{$ips} 个 IP）";
        $text = $first['message']['text'] . "\n\n➕ " . $view->escape($line . '· 最后 ' . date('H:i', $last));
        $user = !empty($first['open']['user_id']) ? User::find((int)$first['open']['user_id']) : null;
        $event = $user && !empty($first['open']['event_id']) ? RiskEvent::find((int)$first['open']['event_id']) : null;
        $keyboard = $user ? ['inline_keyboard' => $view->alertKeyboard($user, $event)] : [];
        try {
            app()->makeWith(TelegramService::class, ['token' => $token])->editMessageText(
                (int)$first['message']['chat_id'], (int)$first['message']['message_id'], $text, 'MarkdownV2', $keyboard);
        } catch (\Throwable $e) {
            if (strpos($e->getMessage(), 'message is not modified') !== false) return;
            $wait = RiskAlertService::retryAfter($e);
            if ($wait === null) throw $e;
            $this->release($wait);
        }
    }
}
