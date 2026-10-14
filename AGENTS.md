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
