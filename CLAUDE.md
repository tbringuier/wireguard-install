# CLAUDE.md

Guidance for AI assistants and contributors working in this repository.

## What this is

A personal fork of [angristan/wireguard-install](https://github.com/angristan/wireguard-install)
that adds public IP routing (failover/additional IPs delivered to WireGuard clients). It is
**not** meant to feed back into upstream and accepts no external contributions. The maintainer
writes to the assistant in French; the repository itself is English-only.

## Hard rules

- **English first, English only**: code, comments, commit messages, documentation, prompts shown
  to the user. No French anywhere in the repository.
- **Not verbose**: short comments that explain *why*, never *what*; no banner comments, no
  restating the code, no defensive logging. One idea per function, small functions.
- **systemd only**: PID 1 must be systemd. No OpenRC, sysvinit or distribution-specific init
  paths. Use `systemctl`, `systemd-detect-virt`, `systemd-sysctl`, `wg-quick@.service` and
  template units; never cron or hand-rolled daemons.
- **Interactive only**: the installer asks questions; there is no unattended/AUTO_INSTALL mode
  (decided by the maintainer, do not add one).
- **Distribution agnostic**: detect the package family from `ID`/`ID_LIKE`, fall back on the
  available package manager. Do not add per-distribution special cases unless a package really
  differs.
- **iptables-nft over native nft**: rules are inserted with `iptables`/`ip6tables` so they win
  over ufw, docker and other default-deny FORWARD policies. A separate nftables table cannot
  override those, so do not "modernise" to `nft` tables.
- **wg-quick over systemd-networkd netdevs**: wg-quick ships with wireguard-tools everywhere and
  supports PostUp/PostDown hooks; networkd is not the network manager on most targets.

## Style

- Bash, tabs, formatted with `shfmt` and clean under `shellcheck -e SC1091,SC1117,SC2001,SC2034`.
- `camelCase` function names, `UPPER_CASE` variables, `local` for everything inside functions.
- Pure "build*" functions return text and take all inputs as arguments so they can be unit
  tested by sourcing the script with `WG_INSTALL_TESTING=1`.
- Generated files (units, scripts, env files) live in `build*` functions, never inline.

## Checks before committing

```bash
shfmt -d wireguard-install.sh
shellcheck -e SC1091,SC1117,SC2001,SC2034 wireguard-install.sh tests/*.sh
tests/run.sh                      # unit tests of the pure functions
tests/smoke-podman.sh debian:13   # optional: full install in a systemd container
```

## Commits

Imperative subject under 60 characters, body wrapped at 72 explaining the why, no conventional
commit prefixes (matches upstream history). Keep upstream history intact; rewrite only the fork's
own commits when asked to clean history.

## Disclosure

Most of the fork (public routing mode, systemd units, tests, documentation) was written with
Claude (Anthropic) and reviewed by the maintainer. Keep that statement in the README and in the
script header.
