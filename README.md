# WireGuard all-in-one installer

![Lint and test](https://github.com/tbringuier/wireguard-install/actions/workflows/lint.yml/badge.svg?branch=master)

One interactive Bash script to install and manage a [WireGuard](https://www.wireguard.com/)
server on any systemd-based Linux host.

- **Classic VPN**: clients get a private tunnel address and browse through the server's public IP.
- **Public IP routing**: the additional or failover IPs your provider routes to the server are
  delivered to clients as-is, without NAT, for self-hosting at home behind the provider's anti-DDoS.
- **Per-client endpoint**: each client connects through the server's IPv6, IPv4 or a hostname.
- **Firewall integration**: ufw and firewalld get the rules WireGuard needs, if you agree.
- **Status view**: every client with its addresses, endpoint, last handshake and traffic.
- **Built on nftables, systemd and Python 3**, nothing else.

It started as a fork of [angristan/wireguard-install](https://github.com/angristan/wireguard-install)
for the tutorial [Avoir des adresses IPv4/IPv6 chez soi avec un tunnel WireGuard](https://blog.folf.fr/wireguard/)
(in French). It does not accept contributions, see [CONTRIBUTING.md](CONTRIBUTING.md).

## Requirements

- systemd as init (PID 1).
- A kernel with WireGuard: 5.6 or later, or the ELRepo module on Enterprise Linux 8.
- `nft` and `python3`, installed by the script where a package manager exists.
- For public IP routing: additional public addresses routed to the server by your provider,
  and not configured on its interfaces.

Supported: Debian 11+, Ubuntu 20.04+, Fedora 32+, Enterprise Linux 8+ (Rocky, AlmaLinux,
CentOS Stream, Oracle Linux), Arch Linux, openSUSE, and their derivatives (detection uses
`ID` and `ID_LIKE` from `/etc/os-release`, then the available package manager). Flatcar
Container Linux works as-is: it ships WireGuard and nftables but no Python, so gratuitous ARP
announcements and IPv6 suggestions are unavailable there.

Cloud images need no preparation: the script works with cloud-init, netplan, systemd-networkd,
NetworkManager and ifupdown, waits for a running cloud-init and for the dpkg lock, and detects
the public address behind cloud 1:1 NAT.

## Usage

```bash
curl -O https://raw.githubusercontent.com/tbringuier/wireguard-install/master/wireguard-install.sh
chmod +x wireguard-install.sh
sudo ./wireguard-install.sh
```

### First run

| Question | Default |
|----------|---------|
| Public IPv4, public IPv6, hostname of the server | detected; leave empty what the server lacks |
| Public interface | the default route's interface |
| WireGuard interface, tunnel MTU | `wg0`, link MTU minus 80 (at most 1420) |
| Tunnel IPv4 and IPv6 subnets, UDP port | `10.66.66.1/24`, `fd42:42:42::1/64`, random port |
| DNS resolvers for clients | Cloudflare |
| Public IP routing, routed IPv6 prefix | `no`; prefix detected on the public interface |
| Add rules to a detected ufw or firewalld | `y` |
| AllowedIPs for clients | everything |

The first client is then created. Later runs show a menu: add a client, show clients and
status, revoke a client, uninstall.

### Clients

Each client has a name, an address mode when public routing is enabled (`private`, `public`
or `mixed`), its addresses and its endpoint. The next free addresses are proposed, including a
public IPv6 taken from the server's prefix. The IPv6 endpoint is recommended when the server
has one: IPv4 addresses attract most attacks. Client files are written in the caller's home
with mode 600 and printed as a QR code when `qrencode` is installed. They carry no hooks and
work unchanged on Linux, Windows, macOS, Android and iOS.

### On the server

```bash
systemctl status wg-quick@wg0
systemctl status wg-public-ipv4-announce@wg0
journalctl -u wg-public-ipv4-announce@wg0
nft list table inet wireguard
wg show
```

| File | Content |
|------|---------|
| `/etc/wireguard/params` | answers given at install time |
| `/etc/wireguard/wg0.conf`, `wg0.conf.bak` | server configuration, regenerated on every change, and its previous version |
| `/etc/wireguard/wg0.nft` | the nftables table |
| `/etc/wireguard/public-ipv4-announce-wg0.env` | addresses announced with gratuitous ARP |
| `/etc/sysctl.d/wg.conf` | forwarding, `accept_ra`, `proxy_ndp` |

## How it works

**Firewall.** `wg-quick` loads one nftables table, `inet wireguard`, when the tunnel comes up
and deletes it when it goes down. The table only holds what the tunnel owns: source NAT for the
private subnets, and TCP MSS clamping to the tunnel MTU in both directions, so clients that
cannot run hooks never hit MTU black holes. Accept rules are deliberately not there: a separate
nftables table cannot override another table's drop policy. When ufw or firewalld is active the
script says what is needed (the UDP port open, forwarding allowed on the tunnel interface),
asks, adds the rules there and removes them on uninstall. Docker's FORWARD policy and foreign
nftables rulesets with a drop policy are reported with the commands to run. ARP is not filtered
by IP firewalls, so gratuitous ARP needs no rule.

**MTU.** The tunnel MTU is asked at install time (link MTU minus the WireGuard overhead, at most
1420) and written in the server and client configurations, which makes the MSS clamp exact.

**Public IP routing.** A public client receives one of the server's additional addresses inside
the tunnel. For each of them the server adds a proxy ARP or proxy NDP entry on the public
interface (`ip neigh proxy`) so it answers for the address, and announces every public IPv4 with
gratuitous ARP every second from `wg-public-ipv4-announce@<interface>`, a template unit bound to
`wg-quick@<interface>`. Some providers only refresh their ARP caches this way. A small Python 3
program sends the frames because `arping` cannot announce an address the host does not own.
Public IPv6 addresses are proposed from the prefix the provider routes to the server.

**Changes.** The server configuration is regenerated from the saved parameters and the
recorded peers on every change, then applied live: peers with `wg syncconf`, the nftables table
with `nft -f`, proxy entries with `ip neigh`. The tunnel is never restarted for a client change.

## Tests

`tests/run.sh` covers the pure functions and runs in CI. `tests/smoke-podman.sh <image>` boots a
systemd container with rootless podman and drives the whole interactive lifecycle: install, add
clients of every mode and endpoint, status, revoke, uninstall, then classic mode.
`FIREWALL=ufw` or `FIREWALL=firewalld` enables that firewall first and checks the integration.
Tested on Debian 12 and 13, Ubuntu 26.04, Fedora, Rocky Linux 9, Arch Linux and openSUSE Leap 15.6.

## About

Most of this project, from the public routing mode to the nftables layer, the systemd units,
the tests and this documentation, was written with [Claude](https://claude.ai) (Anthropic)
under the maintainer's direction, then reviewed and tested by them. Commits carry a
`Co-Authored-By` trailer accordingly.

Upstream project and original author: [angristan/wireguard-install](https://github.com/angristan/wireguard-install),
MIT licence (see [LICENSE](LICENSE)).
