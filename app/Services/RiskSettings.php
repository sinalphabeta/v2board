<?php

namespace App\Services;

use App\Models\RiskSetting;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;

/**
 * Risk-control settings, edited on the admin panel's 风控概览 page and stored in v2_risk_setting.
 * A setting never saved there still comes from .env (config/risk.php), so a deployment keeps working until it is saved.
 * Saved values are cached in Redis (cleared on save) and in each process for a few seconds: webman, php-fpm and Horizon
 * all pick up a change within seconds, without config:cache or a restart. The Redis copy also expires after a minute,
 * in case a request that read the table just before a save writes the old values back after the save cleared them.
 */
class RiskSettings
{
    public const DEFAULTS = [
        'bot_token' => '',
        'alert_chat_id' => '',
        // Who may use the risk bot, one Telegram ID a line with an optional note (RiskOperator); empty: bound admins
        'bot_operators' => '',
        'honeypot_group_id' => 0,
        'ip_info_enabled' => true,
        'asn_cache_ttl' => 3600,
        'trusted_proxies' => '',
        // The access log and what is built on it (RiskAccessService, RiskLinkService); these have no .env fallback
        'access_log_enabled' => true,
        'access_log_days' => 90,
        'sub_daily_limit' => 0,
        'link_detection' => true,
        'link_ip_users' => 3,
        'daily_report' => true,
        // Alerts of each kind a day (RiskAlertService); the rest are only in the risk events and the daily report
        'alert_daily_limit' => 20,
    ];
    private const CACHE_KEY = 'risk:settings';
    private const CACHE_SECONDS = 60;
    private const MEMO_SECONDS = 3;
    // [time, values]: checking a user's nodes reads the honeypot group once per node
    private static $memo;

    public static function get(string $name)
    {
        return self::all()[$name];
    }

    public static function all(): array
    {
        if (self::$memo && self::$memo[0] > microtime(true) - self::MEMO_SECONDS) return self::$memo[1];
        $saved = self::saved();
        $values = [];
        foreach (self::DEFAULTS as $name => $default) {
            $values[$name] = self::cast($name, array_key_exists($name, $saved) ? $saved[$name] : config("risk.{$name}", $default));
        }
        self::$memo = [microtime(true), $values];
        return $values;
    }

    /**
     * The settings read again instead of from this process's memo, for the admin pages that show them right after a save
     * (the request may reach a webman worker that read them a moment before the save).
     */
    public static function fresh(): array
    {
        self::$memo = null;
        return self::all();
    }

    /**
     * Where each setting comes from: 'panel' (saved on the admin panel), 'env' (config/risk.php, from .env) or
     * 'default' (never saved and without an .env fallback).
     */
    public static function sources(): array
    {
        $saved = self::saved();
        $sources = [];
        foreach (array_keys(self::DEFAULTS) as $name) {
            $sources[$name] = array_key_exists($name, $saved) ? 'panel' : (config()->has("risk.{$name}") ? 'env' : 'default');
        }
        return $sources;
    }

    /**
     * Save validated settings; returns the ones that changed as [name => [old, new]].
     */
    public static function save(array $values): array
    {
        self::$memo = null;
        $current = self::all();
        $changes = [];
        DB::transaction(function () use ($values, $current, &$changes) {
            foreach ($values as $name => $value) {
                if (!array_key_exists($name, self::DEFAULTS)) continue;
                $value = self::cast($name, $value);
                RiskSetting::updateOrCreate(['name' => $name], [
                    'value' => is_bool($value) ? ($value ? '1' : '0') : (string)$value,
                    'updated_at' => time(),
                ]);
                if ($value !== $current[$name]) $changes[$name] = [$current[$name], $value];
            }
        });
        try { Cache::forget(self::CACHE_KEY); } catch (\Throwable $e) { }
        self::$memo = null;
        return $changes;
    }

    private static function saved(): array
    {
        try {
            $saved = Cache::get(self::CACHE_KEY);
            if (is_array($saved)) return $saved;
        } catch (\Throwable $e) {
            // The cache is down: read the table
        }
        try {
            $saved = RiskSetting::pluck('value', 'name')->all();
        } catch (\Throwable $e) {
            // No table yet (before update.sql has run), or the database is down: fall back to .env
            return [];
        }
        try { Cache::put(self::CACHE_KEY, $saved, self::CACHE_SECONDS); } catch (\Throwable $e) { }
        return $saved;
    }

    private static function cast(string $name, $value)
    {
        $default = self::DEFAULTS[$name];
        if (is_int($default)) return (int)$value;
        if (is_bool($default)) return filter_var($value, FILTER_VALIDATE_BOOLEAN);
        return trim((string)$value);
    }
}
