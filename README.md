# WireGuard installer with public IP routing

![Lint and test](https://github.com/tbringuier/wireguard-install/actions/workflows/lint.yml/badge.svg)

A Bash script that sets up a [WireGuard](https://www.wireguard.com/) server on a systemd-based
Linux host and, optionally, **routes additional public IP addresses to its clients**: the
failover or additional IPs sold by VPS providers end up directly on a machine at home, behind
the provider's anti-DDoS, with no NAT in between.

It is a personal fork of [angristan/wireguard-install](https://github.com/angristan/wireguard-install)
written for the tutorial [Avoir des adresses IPv4/IPv6 chez soi avec un tunnel WireGuard](https://blog.folf.fr/wireguard/)
(in French). It does not accept contributions, see [CONTRIBUTING.md](CONTRIBUTING.md).

## What it does

**Classic mode** is the upstream behaviour: clients get an address in a private tunnel subnet
and their traffic is NATed behind the server's public IP.

**Public routing mode** adds three kinds of clients:

| Client mode | Tunnel addresses | Traffic |
|-------------|------------------|---------|
| `private`   | one private IPv4/IPv6 from the tunnel subnet | NATed behind the server |
| `public`    | one of the server's additional public IPv4/IPv6 | routed as-is, no NAT |
| `mixed`     | both | both |

For public addresses the server:

- forwards traffic to and from the address without NAT and clamps the TCP MSS to the tunnel
  MTU on the server side, so phones and Windows clients that cannot run hooks work too;
- answers ARP and NDP requests for the address on the public interface (per-address proxy
  entries, `ip neigh proxy`);
- announces each public IPv4 with gratuitous ARP every second from a systemd template unit,
  `wg-public-ipv4-announce@<interface>`, bound to `wg-quick@<interface>`. Some providers only
  refresh their ARP caches this way. A small Python 3 program sends the frames because
  `arping` cannot announce an address the host does not own;
- regenerates its configuration from the saved parameters and peer list on every change, and
  only restarts the tunnel when the firewall hooks changed (a live `wg syncconf` otherwise).

Client files get the matching `PostUp` MSS clamp and can be imported on Linux, Windows, macOS,
Android and iOS (a QR code is printed when `qrencode` is installed).

## Requirements

- systemd as init (PID 1). Non-systemd distributions are not supported.
- A kernel with WireGuard (5.6 or later, or the ELRepo module on Enterprise Linux 8).
- `iptables`/`ip6tables` (the nftables-backed ones are fine). Public routing mode refuses to
  run while firewalld is active.
- For public routing: one or more additional public IPs routed to the server by your
  provider, and `python3` for the gratuitous ARP announcements (installed automatically
  where a package manager exists).

Detection is based on `ID`/`ID_LIKE` in `/etc/os-release` with a fallback on the available
package manager, so derivatives work too. Tested with the container smoke test on:

- Debian 12 and 13, Ubuntu 26.04
- Fedora, Rocky Linux 9 (AlmaLinux, CentOS Stream and Oracle Linux use the same path)
- Arch Linux
- openSUSE Leap 15.6

Flatcar Container Linux is supported as-is (no packages are installed). Debian 11+, Ubuntu
20.04+, Fedora 32+ and Enterprise Linux 8+ are the minimum versions.

The script works with the default network stack of cloud images (cloud-init, netplan,
systemd-networkd, NetworkManager, ifupdown): nothing has to be removed or replaced. It waits
for a running cloud-init and for the dpkg lock before installing packages, detects the public
address behind cloud 1:1 NAT, and keeps router advertisements working once forwarding is on.

## Usage

```bash
curl -O https://raw.githubusercontent.com/tbringuier/wireguard-install/master/wireguard-install.sh
chmod +x wireguard-install.sh
sudo ./wireguard-install.sh
```

Answer the questions (defaults are fine for most of them). Answer `yes` to
*Enable public IP routing support* to get the client address modes above. Run the script again
to add, list or revoke clients, or to uninstall.

Public client addresses must not be configured on the server's own interfaces: if your
provider's cloud-init added the additional IP to the public NIC, remove it from the network
configuration first. The script refuses such addresses and says why.

Useful commands on the server:

```bash
systemctl status wg-quick@wg0
systemctl status wg-public-ipv4-announce@wg0
journalctl -u wg-public-ipv4-announce@wg0
wg show
```

Files: `/etc/wireguard/params` (answers), `/etc/wireguard/wg0.conf` (regenerated, previous
version kept as `wg0.conf.bak`), `/etc/wireguard/public-ipv4-announce-wg0.env` (announced
addresses), `/etc/sysctl.d/wg.conf`.

## Design notes

- `iptables`/`ip6tables` are kept rather than a native nftables table: rules inserted at the
  top of `FORWARD` win over ufw, docker and other default-deny policies, which a separate
  nftables table cannot override. The nftables-backed variant (`iptables-nft`) is installed
  where the distribution offers a choice.
- `wg-quick@.service` is kept rather than systemd-networkd netdevs: it ships with
  wireguard-tools everywhere and supports the `PostUp`/`PostDown` hooks the firewall needs.
- Unit tests (`tests/run.sh`) cover the pure functions; `tests/smoke-podman.sh <image>` runs
  the whole interactive lifecycle in a systemd container with rootless podman.

## About this fork

Most of this fork, from the public routing mode to the systemd units, the tests and this
documentation, was written with [Claude](https://claude.ai) (Anthropic) under the
maintainer's direction and reviewed and tested by them. Commits carry a `Co-Authored-By`
trailer accordingly.

Upstream project and original author: [angristan/wireguard-install](https://github.com/angristan/wireguard-install),
MIT licence (see [LICENSE](LICENSE)).
