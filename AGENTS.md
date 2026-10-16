# AGENTS.md

This repo is a fork of [wyx2685/v2board](https://github.com/wyx2685/v2board) with its own features
(e.g. risk isolation, BEpusdt cashier mode, Shadowrocket status line).

## Upstream sync

- Never merge upstream: no GitHub "Sync fork", no `git merge upstream/master`.
- Port upstream commits one by one: `git cherry-pick -x` if it applies cleanly, otherwise rewrite by hand.
- End each port commit with trailers:
  - `Upstream-Commit: wyx2685/v2board@<full hash>`: the upstream commit it ports (one line each).
  - `Upstream-Synced-To: wyx2685/v2board@<full hash>`: on the last commit of a sync batch.
    Every upstream commit up to and including it is ported or deliberately skipped
    (skipped ones listed with a reason in the body).
- Commits after `99f8526e` without an `Upstream-Commit` trailer are this fork's own changes. Keep them when porting.

## What is missing from upstream?

1. Sync point: `git log -1 --grep='^Upstream-Synced-To:'`.
   If none: `99f8526eddb72a4e8f6cbccd58cc0656bb91fe88`.
2. `git remote add upstream https://github.com/wyx2685/v2board.git` (if missing), `git fetch upstream`, then
   `git log --oneline <sync point>..upstream/master`.
3. Check each commit against the code: this fork may already have it, implemented its own way.

Don't judge by `git log master..upstream/master` or GitHub's "N commits behind":
ported commits are new commits, so the upstream ones always look missing.

## Deploying

The server (BaoTa, PHP 8.1, MySQL 5.7, Redis 7.4.7) runs `./update.sh` after each push: git reset to origin/master,
composer update, `php artisan v2board:update` (runs the whole `database/update.sql` again, then `horizon:terminate`)
and `risk:geoip-update`; the panel's supervisor starts webman and Horizon again. So:

- Code must run on PHP 8.1: no readonly classes, DNF types or other 8.2+ syntax.
- `update.sql` must be safe to run again (`CREATE TABLE IF NOT EXISTS`…), and `install.sql` must give the same
  schema as an upgraded database.
- Rehearse the update in `../demo` before pushing (see its AGENTS.md).

## This fork's risk control

The admin mostly runs it from the Telegram risk bot on a phone; the admin panel's 风控 pages are secondary. Both go
through `RiskService`. Read the code before changing it:

- `app/Services/RiskService.php`: indicator types (`TYPES`; `allow_ip` is the IP allowlist, the others are rules),
  matching and events (`observe()` from login, register and subscription), alerts (`SendRiskTelegramJob`), isolation
  (an email indicator), adding and changing indicators (`addIndicators()`; `saveIndicatorChecked()` keeps the IP list
  and the allowlist apart) and the audit log (`v2_risk_audit`; `changes.reason` explains changes made along the way).
  An alert or event whose IP an IP indicator covers (`ipEntryFor()`, the same IP or a range) offers neither adding it
  to the IP list nor allowlisting it.
- `app/Services/RiskAccessService.php`: the access log `v2_risk_access` (every login, registration, subscription and
  order, one row per day, user, type, result, IP and user agent; an IPv6 address by its /64), the daily subscription
  limit (`guardClient()` in `RiskService`, called from the client middleware), the 10-minute count that alerts 订阅过频
  (`countBurst()`), the nodes' exit IPs (remembered by the node APIs), and old links: a token replaced by any reset is
  kept for 30 days (`rememberOldToken()`, from the User model's `updated` event in `EventServiceProvider`), and the
  client middleware logs a subscription with it as `old_link` before its 403.
- `app/Services/RiskAlertService.php`: keeps alerts from flooding the alert chat. Alerts about one subject (a user, or
  an IP) go out once a day, later ones update that message (`EditRiskAlertJob`, every 5 minutes at most); each kind has
  a daily budget (`alert_daily_limit`); the jobs send at most 15 messages a minute and wait out Telegram's 429.
- `app/Services/RiskLinkService.php`: links between accounts (checked at registration and by `risk:scan` every 10
  minutes, alerted as risk events with a `detail`, never acted on) and the daily report (`risk:summary`, 00:05).
- `app/Services/RiskSettings.php`: settings in `v2_risk_setting`, falling back to `.env` (`config/risk.php`);
  cached in Redis for 60 s and in each process for 3 s, `fresh()` for the admin pages.
- `app/Services/IpInfoService.php`: the qqwry and DB-IP city / ASN databases (`risk:geoip-update`); `lookup()` for
  alerts, `lookupMany()` for the admin lists.
- `app/Plugins/RiskTelegram/`: the risk bot (`RiskBot`, `RiskView`, `Commands/*`). New commands show in Telegram's
  command menu after 设置风险 Bot Webhook on the admin panel. `RiskOperator`: who may use it (the Telegram IDs listed
  in `bot_operators`, or while none are, admins with a bound Telegram account); the audit log records the Telegram ID
  (actor type `tg`).
- `app/Http/Routes/V1/RiskAdminRoute.php` and `app/Http/Controllers/V1/Admin/RiskController.php`: the admin panel's
  `/{secure_path}/risk/*`, kept apart from `AdminRoute` so upstream changes apply cleanly.

## webman

`webman.php` serves on `tcp://127.0.0.1:6600` with `WebmanHttp`, Adapterman's HTTP protocol wrapped so that a body it
cannot parse (bad JSON, an empty body sent as JSON) is answered with 400: Adapterman parses it before onMessage, and an
exception there would stop the whole worker. `composer.json` requires `joanhey/adapterman`, so that `update.sh`'s
`composer update` keeps it (and Workerman) installed.
