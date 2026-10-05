# WireGuard all-in-one installer

![Lint and test](https://github.com/tbringuier/wireguard-install/actions/workflows/lint.yml/badge.svg)

A Bash script that installs and manages a [WireGuard](https://www.wireguard.com/) server on any
systemd-based Linux host, interactively, in one place:

- **Classic VPN**: clients get a private tunnel address and browse through the server's public IP.
- **Public IP routing**: the additional or failover IPs your provider routes to the server are
  delivered to clients as-is, with no NAT, for self-hosting at home behind the provider's anti-DDoS.
- **Per-client endpoint**: each client connects through the server's IPv6, IPv4 or a hostname.
- **Firewall integration**: ufw and firewalld get the rules WireGuard needs, if you agree.
- **Status view**: every client with its addresses, endpoint, last handshake and traffic.
- **nftables, systemd, Python 3**: nothing else.

It started as a fork of [angristan/wireguard-install](https://github.com/angristan/wireguard-install)
for the tutorial [Avoir des adresses IPv4/IPv6 chez soi avec un tunnel WireGuard](https://blog.folf.fr/wireguard/)
(in French) and does not accept contributions, see [CONTRIBUTING.md](CONTRIBUTING.md).

## Usage

```bash
curl -O https://raw.githubusercontent.com/tbringuier/wireguard-install/master/wireguard-install.sh
chmod +x wireguard-install.sh
sudo ./wireguard-install.sh
```

The first run asks for the server's public IPv4, IPv6 and hostname (clients can use any of them
as endpoint), the public interface, the tunnel interface, MTU, addresses and port, the DNS
resolvers for clients, whether to enable public IP routing (and the IPv6 prefix routed to the
server), and whether to add rules to a detected ufw or firewalld. Defaults are fine for most
questions. It then creates the first client.

Later runs show a menu: add a client, show clients and status, revoke a client, uninstall.

Each client asks for a name, an address mode when public routing is enabled (`private`,
`public` or `mixed`), the addresses (the next free one is proposed, including a public IPv6 from
the server's prefix) and the endpoint. The IPv6 endpoint is recommended when the server has one:
IPv4 addresses attract most attacks. A QR code is printed when `qrencode` is installed.

Useful commands on the server:

```bash
systemctl status wg-quick@wg0
systemctl status wg-public-ipv4-announce@wg0
journalctl -u wg-public-ipv4-announce@wg0
nft list table inet wireguard
wg show
```

Files: `/etc/wireguard/params` (answers), `/etc/wireguard/wg0.conf` (regenerated on each
change, previous version in `wg0.conf.bak`), `/etc/wireguard/wg0.nft` (nftables table),
`/etc/wireguard/public-ipv4-announce-wg0.env`, `/etc/sysctl.d/wg.conf`.

## How it works

**Firewall.** The server loads one nftables table, `inet wireguard`, when the tunnel comes up
and removes it when it goes down. It only contains what the tunnel owns: source NAT for the
private tunnel subnets and TCP MSS clamping to the tunnel MTU in both directions, so clients
that cannot run hooks (phones, Windows, routers) never hit MTU black holes. Accept rules are not
in that table, because a separate nftables table cannot override another table's drop policy:
when ufw or firewalld is active, the installer explains what is needed (the UDP port open,
forwarding allowed on the tunnel interface), asks, and adds the rules there, removing them on
uninstall. Docker's FORWARD policy and foreign nftables rulesets with a drop policy are pointed
out with the commands to run. ARP is not filtered by IP firewalls, so gratuitous ARP needs no rule.

**MTU.** The tunnel MTU is the public link MTU minus the WireGuard overhead, capped at 1420,
editable at install time, and written in both the server and client configurations.

**Public routing.** A public client receives one of the server's additional public addresses
inside the tunnel. For each of them the server adds a proxy ARP or proxy NDP entry on the public
interface (`ip neigh proxy`), so it answers for the address, and announces every public IPv4
with gratuitous ARP every second from the template unit `wg-public-ipv4-announce@<interface>`,
bound to `wg-quick@<interface>`: some providers only refresh their ARP caches this way. A small
Python 3 program sends the frames because `arping` cannot announce an address the host does not
own. Adding or revoking a public client updates the proxy entries live, without restarting the
tunnel. Public IPv6 addresses are proposed from the prefix the provider routes to the server.

**Configuration.** The server configuration is regenerated from the saved parameters and the
recorded peers on every change and applied with `wg syncconf`; the tunnel is only restarted when
the hooks themselves changed, such as after an upgrade of this script. Sysctl settings
(forwarding, `accept_ra=2` on the public interface so SLAAC keeps working, `proxy_ndp`) live in
`/etc/sysctl.d/wg.conf`.

## Requirements

- systemd as init (PID 1). Non-systemd distributions are not supported.
- A kernel with WireGuard (5.6 or later, or the ELRepo module on Enterprise Linux 8).
- `nft` (nftables) and `python3`, installed by the script where a package manager exists.
- For public routing: additional public IPs routed to the server by your provider, not
  configured on its interfaces (the script refuses such addresses and says why).

Detection is based on `ID`/`ID_LIKE` in `/etc/os-release` with a fallback on the available
package manager, so derivatives work too. Tested with the container smoke test on Debian 12 and
13, Ubuntu 26.04, Fedora, Rocky Linux 9 (AlmaLinux, CentOS Stream and Oracle Linux use the
same path), Arch Linux and openSUSE Leap 15.6, including ufw and firewalld integration. Flatcar
Container Linux is supported as-is: it ships WireGuard and nftables but no Python, so
gratuitous ARP announcements and IPv6 suggestions are unavailable there. Minimum versions:
Debian 11, Ubuntu 20.04, Fedora 32, Enterprise Linux 8.

The script works with the default network stack of cloud images (cloud-init, netplan,
systemd-networkd, NetworkManager, ifupdown): nothing has to be removed or replaced. It waits
for a running cloud-init and for the dpkg lock before installing packages and detects the
public address behind cloud 1:1 NAT.

## Tests

`tests/run.sh` covers the pure functions. `tests/smoke-podman.sh <image>` boots a systemd
container with rootless podman and drives the whole interactive lifecycle (install, add,
status, revoke, uninstall, classic mode); `FIREWALL=ufw` or `FIREWALL=firewalld` enables that
firewall first and checks the integration.

## About this fork

Most of this project, from the public routing mode to the nftables layer, the systemd units,
the tests and this documentation, was written with [Claude](https://claude.ai) (Anthropic) under
the maintainer's direction and reviewed and tested by them. Commits carry a `Co-Authored-By`
trailer accordingly.

Upstream project and original author: [angristan/wireguard-install](https://github.com/angristan/wireguard-install),
MIT licence (see [LICENSE](LICENSE)).
