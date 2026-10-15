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
- `app/Services/RiskSettings.php`: settings in `v2_risk_setting`, falling back to `.env` (`config/risk.php`);
  cached in Redis for 60 s and in each process for 3 s, `fresh()` for the admin pages.
- `app/Services/IpInfoService.php`: the qqwry and DB-IP city / ASN databases (`risk:geoip-update`); `lookup()` for
  alerts, `lookupMany()` for the admin lists.
- `app/Plugins/RiskTelegram/`: the risk bot (`RiskBot`, `RiskView`, `Commands/*`). New commands show in Telegram's
  command menu after 设置风险 Bot Webhook on the admin panel.
- `app/Http/Routes/V1/RiskAdminRoute.php` and `app/Http/Controllers/V1/Admin/RiskController.php`: the admin panel's
  `/{secure_path}/risk/*`, kept apart from `AdminRoute` so upstream changes apply cleanly.
