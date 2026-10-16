<?php

namespace App\Plugins\RiskTelegram;

use App\Models\User;
use App\Services\RiskService;
use App\Services\RiskSettings;

/**
 * Someone allowed to use the risk bot: a Telegram ID listed in 可操作的 Telegram ID (the bot_operators setting), or
 * while none are listed, an admin whose Telegram account is bound (telegram_id). The audit log records their Telegram
 * ID ('tg').
 */
class RiskOperator
{
    // What Telegram sends as the sender of a group's anonymous admins
    public const ANONYMOUS_ADMIN = 1087968824;

    public $telegramId;
    public $user;

    public function __construct(int $telegramId, ?User $user = null)
    {
        $this->telegramId = $telegramId;
        $this->user = $user;
    }

    public static function find(int $telegramId): ?self
    {
        if ($telegramId <= 0 || $telegramId === self::ANONYMOUS_ADMIN) return null;
        $listed = self::listed();
        if ($listed) return array_key_exists($telegramId, $listed) ? new self($telegramId, self::boundUser($telegramId)) : null;
        $admin = User::where('telegram_id', $telegramId)->where('is_admin', 1)->first();
        return $admin ? new self($telegramId, $admin) : null;
    }

    /**
     * The listed Telegram IDs and their notes: [id => note, possibly ''].
     */
    public static function listed(): array
    {
        $listed = [];
        foreach (preg_split('/[\r\n,，]+/u', (string)RiskSettings::get('bot_operators')) as $entry) {
            if (preg_match('/^\s*(\d+)(?:\s+(.*\S))?\s*$/u', $entry, $match)) $listed[(int)$match[1]] = $match[2] ?? '';
        }
        return $listed;
    }

    /**
     * How the audit log shows a Telegram ID: its note, else the email of the user bound to it, then the ID.
     */
    public static function nameOf(int $telegramId): string
    {
        $note = self::listed()[$telegramId] ?? '';
        if ($note === '') {
            $user = self::boundUser($telegramId);
            $note = $user ? (string)$user->email : '';
        }
        return $note !== '' ? "{$note}（TG {$telegramId}）" : "TG {$telegramId}";
    }

    /**
     * A RiskService that records changes as made by this operator.
     */
    public function service(): RiskService
    {
        return (new RiskService())->actingAs('tg', $this->telegramId);
    }

    private static function boundUser(int $telegramId): ?User
    {
        return User::where('telegram_id', $telegramId)->orderByDesc('is_admin')->first();
    }
}
