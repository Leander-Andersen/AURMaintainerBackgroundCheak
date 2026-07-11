# AURMaintainerBackgroundCheak

A full-system upgrade front-end for `paru`/`yay`: it vets pending **AUR**
updates against known breach indicators, lists pending **official-repo**
updates as pre-cleared, and lets you install both together — so you get one
"is it safe to upgrade today" prompt instead of blind-firing `paru`/`yay -Sua`
(or juggling a separate repo-update step).

Built in response to the June 2026 **"Atomic Arch"** supply-chain attack, in which
attackers adopted ~1,500 orphaned AUR packages and injected credential-stealing
malware (`atomic-lockfile` / `js-digest`), mostly modified in the **June 9–12 2026**
window. Arch's official repos (`core`/`extra`/`multilib`) were unaffected — this is
an AUR-only problem, and the fix is vetting *who changed your packages and when*.

Official-repo updates are listed too (folded into the same table as trusted
`RECOMMENDED` rows, since repos weren't part of the attack), but everything —
repo and AUR alike — is only ever installed by explicit package name via
`paru`/`yay -S --needed <names>`. This tool never shells out to a blanket
`-Syu`/`-Sua`; that blind-firing is exactly what it exists to replace.

This tool is **complementary** to
[lenucksi/aur-malware-check](https://github.com/lenucksi/aur-malware-check) (which
hunts already-installed malware / rootkit artifacts). It reuses that project's
community IOC lists, but its own job is **safe updating going forward**.

## What it does

For every AUR package with an available update, plus every official-repo package
with a pending update, it shows one colorized table and a verdict per package,
then lets you update only the cleared ones — repo and AUR together, in a single
step:

```
PACKAGE                      VERSION                MAINTAINER       LAST ACTIVITY CHG  POP/VOTES    VERDICT
------------------------------------------------------------------------------------------------------------
some-evil-pkg                1.0-1 -> 1.1-1         custodiatovar    18d ago       YES  0.10/4       BLOCKED
old-orphan-thing             2.0-1 -> 2.1-1         —                40d ago            0.05/2       CAUTION
tiny-leaf-theme              3.0-1 -> 3.1-1         alice            5d ago             0.02/3       OPTIONAL
visual-studio-code-bin       1.125-1 -> 1.126-1     dcelasun         4d ago             30.9/1689    RECOMMENDED
linux-firmware                20260601-1 -> 20260701-1 official repo  trusted            —            RECOMMENDED

  some-evil-pkg: maintainer changed: alice -> custodiatovar; maintainer 'custodiatovar' is a flagged attacker account

4 recommended, 1 blocked. Audit: ~/.local/state/aurcheck/cleared-2026-06-29.csv

Update [a]ll / [r]ecommended / [q]uit?
```

### Verdicts

| Verdict | Color | Meaning |
|---------|-------|---------|
| `BLOCKED` | red | Matches a breach indicator — excluded from "recommended" |
| `CAUTION` | yellow | Orphaned (no maintainer) — adopt-bait; review manually |
| `OPTIONAL` | yellow | Cleared but a minor leaf package — safe to defer |
| `RECOMMENDED` | green | Cleared and worth updating (depended-on / popular), **or** an official-repo package |
| `UNKNOWN` | dim | Foreign package not found on the AUR (locally built, etc.) |

### How a verdict is chosen (first match wins)

0. **In an official repo** (`core`/`extra`/`multilib`, i.e. listed by `paru`/`yay -Qu`
   after a sync)? → `RECOMMENDED`, reason `official repo, trusted`. Skips every
   check below — those repos weren't part of the attack, so there's nothing to vet.
1. **Whitelisted?** → `RECOMMENDED`. Your `whitelist.txt` overrides everything below.
2. **Not on the AUR?** → `UNKNOWN`. Never auto-updated.
3. **Any breach indicator?** → `BLOCKED` if **any** of these hold:
   - current maintainer is a **flagged attacker account**
     (status `confirmed`/`monitoring` — *not* an impersonated `commitforgery` name),
   - it's on the **known compromised-package list**,
   - it was **modified during the June 9–12 2026 attack window**, or
   - its **maintainer changed since your last run** (`CHG = YES`).
4. **Orphaned** (no maintainer)? → `CAUTION`.
5. **Otherwise cleared** → `RECOMMENDED` vs `OPTIONAL`, by the heuristic below.

### Recommended vs optional (the thresholds)

A cleared package is **`RECOMMENDED`** (worth updating) if **any** of these hold,
otherwise it's **`OPTIONAL`** (a minor leaf you can safely defer):

| Signal | Constant | Value |
|--------|----------|-------|
| Another installed package depends on it (`pacman -Qi` → Required By ≠ None) | — | — |
| AUR popularity | `POP_THRESHOLD` | `≥ 1.0` |
| AUR votes | `VOTES_THRESHOLD` | `≥ 10` |

So **`OPTIONAL`** = a leaf package nothing depends on, with popularity `< 1.0`
**and** fewer than `10` votes.

> **"Not recommended" means two different things.** `BLOCKED`/`CAUTION` are
> *unsafe / unverifiable* and are excluded from updates on purpose. `OPTIONAL` is
> *safe but trivial* — excluded from the one-shot recommended update only because
> it's low-importance. Choosing **[r]** installs **only** `RECOMMENDED` packages.

All three thresholds (`POP_THRESHOLD`, `VOTES_THRESHOLD`, and the attack window
epochs) are constants at the top of both scripts, so they're easy to tune.

> **Note on maintainer history:** the AUR API exposes only the *current*
> maintainer, not a change log. So change detection works by storing a local
> **snapshot** each run and diffing against it. The first run establishes the
> baseline; the June 9–12 window + attacker-account + compromised-list checks
> cover the historical signal.

## Two versions

| File | Runtime | Dependencies |
|------|---------|--------------|
| `aurcheck.py` | Python 3 | standard library only |
| `aurcheck`    | Bash     | `curl`, `jq`, `pacman`, `paru`/`yay`, coreutils |

Both behave identically. Pick whichever you prefer.

## Usage

```bash
./aurcheck            # or: python3 aurcheck.py
./aurcheck --refresh  # re-fetch the IOC lists from upstream first
./aurcheck --helper yay
./aurcheck --yes      # non-interactive: update RECOMMENDED, no prompt
./aurcheck --no-color # for those beyond hope
```

Pick the update action at the prompt:

- **`r` (recommended)** → runs `paru -S --needed <RECOMMENDED packages>` (AUR + official-repo)
- **`a` (all)** → runs `paru -S --needed <every listed package>`, AUR and repo alike, by
  explicit name (warns + reconfirms if anything is `BLOCKED`) — never a blanket `-Syu`/`-Sua`
- **`q` (quit)** → changes nothing; the snapshot is still updated for next time

Before listing anything, the tool runs one repo-database sync via the helper
(`paru`/`yay -Sy`, falling back to `pacman -Sy` only if that fails) — the single
root prompt for the whole run. Everything after that (`-Qua`, `-Qu`, `-S --needed`)
goes through `paru`/`yay`, never bare `pacman`, to keep this strictly an
AUR-helper-centric tool.

## Files & data locations

| Path | Purpose |
|------|---------|
| `data/` | Bundled IOC snapshot (offline fallback) |
| `~/.cache/aurcheck/` | Refreshable IOC lists (from lenucksi upstream) |
| `~/.config/aurcheck/whitelist.txt` | **Your** vetted packages (one name per line) — never blocked |
| `~/.local/state/aurcheck/snapshot.json` | Maintainer baseline for change detection |
| `~/.local/state/aurcheck/cleared-<date>.csv` | Per-run audit record |

### Whitelisting a package you've personally verified

```bash
echo my-trusted-pkg >> ~/.config/aurcheck/whitelist.txt
```

## Limitations

- Detects maintainer *changes* only from your second run onward (snapshot-based).
- Does not scan for installed malware / rootkits — use
  [lenucksi/aur-malware-check](https://github.com/lenucksi/aur-malware-check) for that.
- IOC lists are community-maintained and necessarily incomplete; treat
  `RECOMMENDED` as "no *known* indicator", not "proven safe".

## Credits

IOC data (compromised packages, attacker accounts, malicious npm names) from
[lenucksi/aur-malware-check](https://github.com/lenucksi/aur-malware-check),
consolidated from the Arch community's response to the attack.
