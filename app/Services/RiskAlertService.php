<?php

namespace App\Services;

use App\Jobs\EditRiskAlertJob;
use App\Jobs\SendRiskTelegramJob;
use App\Models\RiskEvent;
use App\Models\User;
use App\Plugins\RiskTelegram\RiskView;
use Illuminate\Support\Facades\Cache;

/**
 * Keeps risk alerts (RiskService::notify(), the only way in) from flooding the alert chat:
 * - Merging: alerts about one subject (a user, or an IP when there is no user; the IP of 注册关联) go out once a day.
 *   Later ones are not sent but update a line at the end of that first message, at most every EDIT_DELAY seconds
 *   (an edit does not notify), and the REMIND_AT-th of them is sent again as a reply to it. Once a button of the alert
 *   was pressed, or the user was isolated, the subject is closed for the day: later alerts are only counted.
 * - Budget: at most alert_daily_limit alerts of each kind a day; the rest are only in the risk events and the daily
 *   report, and a notice says so when a kind reaches it.
 * - Pace: the alert jobs send at most PER_MINUTE messages a minute (Telegram allows a group about 20) and wait for a
 *   free slot otherwise, and wait as long as Telegram asks after a 429.
 * Redis keeps the state; when it is down, every alert goes out as before.
 */
class RiskAlertService
{
    public const EDIT_DELAY = 300;
    public const REMIND_AT = 10;
    public const PER_MINUTE = 15;
    // Kinds of alert for the budget besides the finding types: a request matching the rules, an isolated user's request
    public const KINDS = ['hit' => '命中名单', 'isolated' => '已隔离用户的请求'] + RiskService::FINDING_TYPES;
    private const TTL = 2 * 86400;

    /**
     * The subject of an alert about a request (RiskService::recordEvent()): its user, or its IP (an IPv6 /64).
     */
    public function requestSubject(?User $user, string $ip): string
    {
        return $user ? 'user:' . (int)$user->id : 'ip:' . (new RiskAccessService())->ipNet($ip);
    }

    /**
     * Where an alert about $subject stands today: 'first' (send it), 'merged' (counted into today's first alert, which
     * is updated in a while) or 'closed' (only counted). $eventId: the event of the alert, kept for the first one.
     */
    public function gate(string $subject, ?int $eventId, ?int $userId): string
    {
        try {
            $day = date('Ymd');
            $hash = md5($subject);
            if (Cache::get("risk:alert:closed:{$hash}:{$day}")) {
                $this->countMerged($hash, $day);
                return 'closed';
            }
            if (Cache::add("risk:alert:open:{$hash}:{$day}", ['event_id' => $eventId, 'user_id' => $userId, 'at' => time(), 'subject' => $subject], self::TTL)) {
                return 'first';
            }
            $merged = $this->countMerged($hash, $day);
            // The edit runs later and shows everything merged by then
            if (Cache::add("risk:alert:edit:{$hash}", 1, self::EDIT_DELAY)) {
                EditRiskAlertJob::dispatch($subject, $day)->delay(self::EDIT_DELAY);
            }
            return $merged === self::REMIND_AT ? 'remind' : 'merged';
        } catch (\Throwable $e) {
            return 'first';
        }
    }

    /**
     * Stop updating and reminding today's alert about $subject: its user was isolated, or a button of it was pressed.
     */
    public function close(string $subject): void
    {
        try { Cache::put('risk:alert:closed:' . md5($subject) . ':' . date('Ymd'), 1, self::TTL); } catch (\Throwable $e) { }
    }

    /**
     * A button of a message was pressed: if it is an alert (or its reminder), close its subject for its day.
     */
    public function closeMessage(int $chatId, int $messageId): void
    {
        try {
            $alert = Cache::get("risk:alert:of:{$chatId}:{$messageId}");
            if (is_array($alert)) Cache::put("risk:alert:closed:{$alert['hash']}:{$alert['day']}", 1, self::TTL);
        } catch (\Throwable $e) { }
    }

    /**
     * Remember a sent alert about $subject on $day (when it was let through): the first one keeps its text for the
     * edits, and any one's buttons can close the subject.
     */
    public function sent(string $subject, string $day, int $chatId, int $messageId, string $text, bool $first): void
    {
        try {
            $hash = md5($subject);
            if ($first) Cache::put("risk:alert:msg:{$hash}:{$day}", ['chat_id' => $chatId, 'message_id' => $messageId, 'text' => $text], self::TTL);
            Cache::put("risk:alert:of:{$chatId}:{$messageId}", ['hash' => $hash, 'day' => $day], self::TTL);
        } catch (\Throwable $e) { }
    }

    /**
     * Today's first alert about $subject as sent ([chat_id, message_id, text]) and when it was opened, or null.
     */
    public function first(string $subject, string $day): ?array
    {
        try {
            $hash = md5($subject);
            $open = Cache::get("risk:alert:open:{$hash}:{$day}");
            $message = Cache::get("risk:alert:msg:{$hash}:{$day}");
            if (!is_array($open)) return null;
            return ['open' => $open, 'message' => is_array($message) ? $message : null,
                'closed' => (bool)Cache::get("risk:alert:closed:{$hash}:{$day}")];
        } catch (\Throwable $e) {
            return null;
        }
    }

    /**
     * What was merged into the first alert about $subject since it was opened: [count, IPs (an IPv6 /64 as one),
     * last time, user ids], from the risk events.
     */
    public function mergedSince(string $subject, array $open): array
    {
        $access = new RiskAccessService();
        $query = RiskEvent::where('first_seen_at', '>=', (int)$open['at'])->where('id', '!=', (int)($open['event_id'] ?? 0));
        [$kind, $value] = explode(':', $subject, 2);
        if ($kind === 'user') {
            $events = $query->where('user_id', (int)$value)->whereNotIn('event_type', array_keys(RiskService::FINDING_TYPES))->get();
        } elseif ($kind === 'register') {
            $events = $query->where('event_type', 'register_link')->get()->filter(function (RiskEvent $event) use ($access, $value) {
                return $access->ipNet((string)$event->ip) === $value;
            });
        } else {
            $events = $query->whereNull('user_id')->get()->filter(function (RiskEvent $event) use ($access, $value) {
                return $access->ipNet((string)$event->ip) === $value;
            });
        }
        return [
            $events->count(),
            $events->map(function (RiskEvent $event) use ($access) { return $access->ipNet((string)$event->ip); })->unique()->count(),
            (int)$events->max('last_seen_at'),
            $events->pluck('user_id')->filter()->unique()->values()->all(),
        ];
    }

    /**
     * Whether another alert of $kind (a key of KINDS) may go out today. The first one over the budget sends a notice.
     */
    public function withinBudget(string $kind, $chatId): bool
    {
        try {
            $day = date('Ymd');
            $key = "risk:alert-budget:{$kind}:{$day}";
            Cache::add($key, 0, self::TTL);
            $count = (int)Cache::increment($key);
            $budget = $this->dailyLimit();
            if ($count <= $budget) return true;
            $skipped = "risk:alert-skipped:{$kind}:{$day}";
            Cache::add($skipped, 0, self::TTL);
            Cache::increment($skipped);
            if ($count === $budget + 1 && $chatId) {
                $name = self::KINDS[$kind] ?? $kind;
                SendRiskTelegramJob::dispatch((int)$chatId, (new RiskView())->escape(
                    "⚠️ 今天的「{$name}」告警已发满 {$budget} 条，后面的只记进风险事件和日报（每类每天的上限在风控概览里改）"));
            }
            return false;
        } catch (\Throwable $e) {
            return true;
        }
    }

    public function dailyLimit(): int
    {
        return max(1, (int)RiskSettings::get('alert_daily_limit'));
    }

    /**
     * Count a finding not alerted because its user is quiet (免告警), for the daily report.
     */
    public function quieted(): void
    {
        try {
            $key = 'risk:alert-quiet:' . date('Ymd');
            Cache::add($key, 0, self::TTL);
            Cache::increment($key);
        } catch (\Throwable $e) { }
    }

    /**
     * How many alerts were left out on the day of $time for going over the daily budget, how many were merged, and
     * how many findings about quiet users were not alerted.
     */
    public function dayCounts(?int $time = null): array
    {
        $day = date('Ymd', $time ?? time());
        $skipped = 0;
        try {
            foreach (array_keys(self::KINDS) as $kind) $skipped += (int)Cache::get("risk:alert-skipped:{$kind}:{$day}", 0);
            $merged = (int)Cache::get("risk:alert:merged-total:{$day}", 0);
            $quiet = (int)Cache::get("risk:alert-quiet:{$day}", 0);
        } catch (\Throwable $e) {
            [$merged, $quiet] = [0, 0];
        }
        return ['skipped' => $skipped, 'merged' => $merged, 'quiet' => $quiet];
    }

    /**
     * A sending slot in the current minute (PER_MINUTE at most), or the seconds to wait for the next minute.
     */
    public function slot(): int
    {
        try {
            $key = 'risk:alert:rate:' . date('YmdHi');
            Cache::add($key, 0, 120);
            if ((int)Cache::increment($key) <= self::PER_MINUTE) return 0;
            return 60 - (int)date('s') + random_int(1, 5);
        } catch (\Throwable $e) {
            return 0;
        }
    }

    /**
     * The seconds Telegram asks to wait, if the error is its 429 (Too Many Requests: retry after N).
     */
    public static function retryAfter(\Throwable $e): ?int
    {
        return preg_match('/Too Many Requests: retry after (\d+)/i', $e->getMessage(), $match) ? (int)$match[1] + 1 : null;
    }

    private function countMerged(string $hash, string $day): int
    {
        $key = "risk:alert:merged:{$hash}:{$day}";
        Cache::add($key, 0, self::TTL);
        $total = "risk:alert:merged-total:{$day}";
        Cache::add($total, 0, self::TTL);
        Cache::increment($total);
        return (int)Cache::increment($key);
    }
}
