#!/bin/bash
# Full install / add / revoke / uninstall run inside a systemd container.
# Rootless podman is enough: the container gets its own network namespace and the
# WireGuard, nftables and arping code paths all run inside it.
#
# Usage: tests/smoke-podman.sh <base image>        e.g. docker.io/library/debian:13
#        tests/smoke-podman.sh wgtest-<name>        reuse an image built by a previous run
# FIREWALL=ufw|firewalld enables that firewall in the container first and answers yes
# to the integration prompt (ufw on apt systems, firewalld on dnf systems).
# shellcheck disable=SC2016  # single quotes are deliberate: commands run inside the container
set -euo pipefail

IMAGE=${1:?usage: $0 <base image | wgtest-image>}
FIREWALL=${FIREWALL:-none}
cd "$(dirname "$0")/.."

if [[ ${IMAGE} == wgtest-* ]]; then
	TEST_IMAGE=${IMAGE}
else
	TEST_IMAGE="wgtest-$(echo "${IMAGE##*/}" | tr -c 'a-zA-Z0-9\n' '-')"
	case "${IMAGE}" in
	*debian* | *ubuntu*) PREPARE='apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends systemd systemd-sysv iproute2 procps ca-certificates kmod' ;;
	*fedora* | *rocky* | *alma* | *centos*) PREPARE='dnf -y install systemd iproute procps-ng util-linux' ;;
	*arch*) PREPARE='pacman -Syu --noconfirm --needed systemd iproute2 procps-ng' ;;
	*suse*) PREPARE='zypper --non-interactive install systemd iproute2 procps' ;;
	*)
		echo "No recipe to add systemd to ${IMAGE}" >&2
		exit 1
		;;
	esac
	echo "Building ${TEST_IMAGE} from ${IMAGE}"
	podman build -q -t "${TEST_IMAGE}" -f - . <<CONTAINERFILE
FROM ${IMAGE}
RUN ${PREPARE}
CMD ["/usr/lib/systemd/systemd"]
CONTAINERFILE
fi

CONTAINER="${TEST_IMAGE}-$$"
trap 'podman rm -f "${CONTAINER}" >/dev/null 2>&1 || true' EXIT
podman run -d --name "${CONTAINER}" --systemd=always --privileged "${TEST_IMAGE}" >/dev/null

function inside() {
	podman exec "${CONTAINER}" "$@"
}

for _ in $(seq 1 30); do
	STATE=$(inside systemctl is-system-running 2>/dev/null || true)
	[[ ${STATE} == running || ${STATE} == degraded ]] && break
	sleep 1
done
echo "Container ${CONTAINER} is ${STATE:-not booting}"

PASSED=0
FAILED=0
function check() {
	# check <description> <command run inside the container...>
	local DESCRIPTION=$1
	shift
	if inside "$@" >/dev/null 2>&1; then
		PASSED=$((PASSED + 1))
	else
		FAILED=$((FAILED + 1))
		echo "FAIL: ${DESCRIPTION}" >&2
	fi
}

function runInstaller() {
	# Answers come from stdin; without a tty the defaults are not applied, so every
	# prompt gets an explicit value.
	podman exec -i "${CONTAINER}" bash /root/wireguard-install.sh >"${LOG}" 2>&1 || {
		echo "installer exited with status $?" >&2
		tail -40 "${LOG}" >&2
	}
}

LOG=$(mktemp)
trap 'rm -f "${LOG}"; podman rm -f "${CONTAINER}" >/dev/null 2>&1 || true' EXIT
podman cp wireguard-install.sh "${CONTAINER}:/root/wireguard-install.sh"
NIC=$(inside sh -c "ip -o -4 route show default | awk '{for (i = 1; i <= NF; i++) if (\$i == \"dev\") print \$(i + 1)}' | head -1")
echo "Public interface inside the container: ${NIC}"

# A unit from the previous generation of this fork must be migrated away
inside sh -c 'printf "[Service]\nExecStart=/bin/true\n" >/etc/systemd/system/wg-public-ipv4-arping.service'

case "${FIREWALL}" in
ufw)
	echo "== enabling ufw"
	inside sh -c 'apt-get -qq update >/dev/null && DEBIAN_FRONTEND=noninteractive apt-get -qq install -y ufw >/dev/null && ufw --force enable >/dev/null'
	;;
firewalld)
	echo "== enabling firewalld"
	inside sh -c 'dnf -q -y install firewalld >/dev/null && systemctl enable --now firewalld >/dev/null && sleep 2'
	;;
esac

function installAnswers() {
	# installAnswers <public routing yes|no>: one line per prompt, defaults are not
	# applied without a tty so every value is explicit
	printf '%s\n' 198.51.100.1 2001:db8:1::1 vpn.example.com "${NIC}" wg0 1420 10.66.66.1 fd42:42:42::1 51820 1.1.1.1 1.0.0.1 "$1"
	[[ $1 == yes ]] && printf '%s\n' 2001:db8:1::/64
	[[ ${FIREWALL} != none ]] && printf 'y\n'
	printf '%s\n' 0.0.0.0/0,::/0 ''
}

echo "== install in public routing mode with a public client"
{
	installAnswers yes
	printf '%s\n' alice public 203.0.113.50 2001:db8:1::50 1
} | runInstaller
check "tunnel is active" systemctl is-active --quiet wg-quick@wg0
check "tunnel is enabled" systemctl is-enabled --quiet wg-quick@wg0
check "one peer configured" sh -c '[ "$(wg show wg0 peers | wc -l)" = 1 ]'
check "announcement unit is active" systemctl is-active --quiet wg-public-ipv4-announce@wg0
check "announcement unit is enabled" systemctl is-enabled --quiet wg-public-ipv4-announce@wg0
check "announcement unit logs its addresses" sh -c 'journalctl -u wg-public-ipv4-announce@wg0 --no-pager | grep -q "Announcing 203.0.113.50 on"'
check "announcement unit has no failures" sh -c '! journalctl -u wg-public-ipv4-announce@wg0 --no-pager | grep -q -E "Cannot announce|Traceback"'
check "legacy unit removed" sh -c '! test -e /etc/systemd/system/wg-public-ipv4-arping.service'
check "nft table loaded" nft list table inet wireguard
check "mss clamp on the server" sh -c 'nft list table inet wireguard | grep -q "maxseg size set 1380"'
check "private subnet is NATed" sh -c 'nft list table inet wireguard | grep -q "ip saddr 10.66.66.0/24 masquerade"'
check "tunnel mtu applied" sh -c 'ip link show wg0 | grep -q "mtu 1420"'
check "arp proxy entry" sh -c 'ip -4 neigh show proxy | grep -q 203.0.113.50'
check "ndp proxy entry" sh -c 'ip -6 neigh show proxy | grep -q 2001:db8:1::50'
check "proxy_ndp enabled" sh -c '[ "$(sysctl -n net.ipv6.conf.all.proxy_ndp)" = 1 ]'
check "forwarding enabled" sh -c '[ "$(sysctl -n net.ipv4.ip_forward)" = 1 ] && [ "$(sysctl -n net.ipv6.conf.all.forwarding)" = 1 ]'
check "accept_ra on the public nic" sh -c "[ \"\$(sysctl -n net.ipv6.conf.${NIC}.accept_ra)\" = 2 ]"
check "client file written" test -s /root/wg0-client-alice.conf
check "client addresses" grep -q "Address = 203.0.113.50/32,2001:db8:1::50/128" /root/wg0-client-alice.conf
check "client endpoint is the IPv6 one" grep -q "Endpoint = \[2001:db8:1::1\]:51820" /root/wg0-client-alice.conf
check "endpoint recorded for the peer" grep -q "# Endpoint: \[2001:db8:1::1\]:51820" /etc/wireguard/wg0.conf
check "server side keepalive" grep -q "PersistentKeepalive = 15" /etc/wireguard/wg0.conf
check "client carries the tunnel mtu and no hooks" sh -c 'grep -q "MTU = 1420" /root/wg0-client-alice.conf && ! grep -q PostUp /root/wg0-client-alice.conf'
check "client file is private" sh -c '[ "$(stat -c %a /root/wg0-client-alice.conf)" = 600 ]'
check "server config is private" sh -c '[ "$(stat -c %a /etc/wireguard/wg0.conf)" = 600 ] && [ "$(stat -c %a /etc/wireguard)" = 700 ]'
check "env file is private" sh -c '[ "$(stat -c %a /etc/wireguard/public-ipv4-announce-wg0.env)" = 600 ]'

case "${FIREWALL}" in
ufw)
	check "ufw allows the port" sh -c 'ufw status | grep -q "51820/udp"'
	# ufw lists each route rule twice (IPv4 and IPv6)
	check "ufw allows forwarding" sh -c '[ "$(ufw status | grep -c "ALLOW FWD")" -ge 2 ]'
	;;
firewalld)
	check "firewalld opens the port" sh -c 'firewall-cmd --list-ports | grep -q 51820/udp'
	check "firewalld trusts the tunnel" sh -c 'firewall-cmd --zone=trusted --list-interfaces | grep -q wg0'
	check "firewalld forwarding policies" sh -c 'firewall-cmd --get-policies | grep -q wg-forward-in && firewall-cmd --get-policies | grep -q wg-forward-out'
	;;
esac

echo "== add a private client (no hook change: live sync, no restart)"
STARTED_BEFORE=$(inside systemctl show -p ActiveEnterTimestamp --value wg-quick@wg0)
printf '%s\n' 1 bob private 10.66.66.2 fd42:42:42::2 2 | runInstaller
check "private client got the IPv4 endpoint" grep -q "Endpoint = 198.51.100.1:51820" /root/wg0-client-bob.conf
check "two peers" sh -c '[ "$(wg show wg0 peers | wc -l)" = 2 ]'
check "tunnel was not restarted" sh -c "[ \"\$(systemctl show -p ActiveEnterTimestamp --value wg-quick@wg0)\" = '${STARTED_BEFORE}' ]"
check "previous config backed up" test -s /etc/wireguard/wg0.conf.bak

echo "== add a mixed client with a second public IPv4"
printf '%s\n' 1 carol mixed 10.66.66.3 fd42:42:42::3 203.0.113.51 '' 4 wg.example.org | runInstaller
check "custom endpoint accepted" grep -q "Endpoint = wg.example.org:51820" /root/wg0-client-carol.conf
check "three peers" sh -c '[ "$(wg show wg0 peers | wc -l)" = 3 ]'
check "both public addresses announced" grep -q 'PUBLIC_IPV4_LIST="203.0.113.50 203.0.113.51"' /etc/wireguard/public-ipv4-announce-wg0.env
check "announcement restarted with both" sh -c 'journalctl -u wg-public-ipv4-announce@wg0 --no-pager | grep -q "Announcing 203.0.113.50 203.0.113.51 on"'
check "second arp proxy entry" sh -c 'ip -4 neigh show proxy | grep -q 203.0.113.51'
check "public client added without restart" sh -c "[ \"\$(systemctl show -p ActiveEnterTimestamp --value wg-quick@wg0)\" = '${STARTED_BEFORE}' ]"

echo "== reject a duplicate client name and a bad address, then succeed"
printf '%s\n' 1 bob dave private 10.66.66.2 10.66.66.4 fd42:42:42::4 3 | runInstaller
check "hostname endpoint" grep -q "Endpoint = vpn.example.com:51820" /root/wg0-client-dave.conf
check "four peers after corrected input" sh -c '[ "$(wg show wg0 peers | wc -l)" = 4 ]'
check "duplicate address was refused" grep -q "AllowedIPs = 10.66.66.4/32,fd42:42:42::4/128" /etc/wireguard/wg0.conf

echo "== status view"
printf '%s\n' 2 | runInstaller
for EXPECTED in 'alice +public +203.0.113.50, 2001:db8:1::50 +\[2001:db8:1::1\]:51820 +\(none\) +never' 'carol +mixed +203.0.113.51, 10.66.66.3, fd42:42:42::3 +wg.example.org:51820' 'Announcements +active for: 203.0.113.50 203.0.113.51' 'Proxy entries .*203.0.113.50'; do
	if grep -q -E "${EXPECTED}" "${LOG}"; then
		PASSED=$((PASSED + 1))
	else
		FAILED=$((FAILED + 1))
		echo "FAIL: status shows: ${EXPECTED}" >&2
	fi
done

echo "== revoke the public client"
printf '%s\n' 3 1 | runInstaller
check "three peers left" sh -c '[ "$(wg show wg0 peers | wc -l)" = 3 ]'
check "arp proxy entry removed" sh -c '! ip -4 neigh show proxy | grep -q 203.0.113.50'
check "ndp proxy entry removed" sh -c '! ip -6 neigh show proxy | grep -q 2001:db8:1::50'
check "remaining arp proxy kept" sh -c 'ip -4 neigh show proxy | grep -q 203.0.113.51'
check "public client revoked without restart" sh -c "[ \"\$(systemctl show -p ActiveEnterTimestamp --value wg-quick@wg0)\" = '${STARTED_BEFORE}' ]"
check "client file removed" sh -c '! test -e /root/wg0-client-alice.conf'
check "announcement keeps the remaining address" grep -q 'PUBLIC_IPV4_LIST="203.0.113.51"' /etc/wireguard/public-ipv4-announce-wg0.env
check "announcement unit still active" systemctl is-active --quiet wg-public-ipv4-announce@wg0

echo "== revoke the mixed client: nothing left to announce"
printf '%s\n' 3 2 | runInstaller
check "two peers left" sh -c '[ "$(wg show wg0 peers | wc -l)" = 2 ]'
check "announcement unit stopped" sh -c '! systemctl is-active --quiet wg-public-ipv4-announce@wg0'
check "announcement unit disabled" sh -c '! systemctl is-enabled --quiet wg-public-ipv4-announce@wg0'
check "env file removed" sh -c '! test -e /etc/wireguard/public-ipv4-announce-wg0.env'
check "tunnel still active" systemctl is-active --quiet wg-quick@wg0

echo "== uninstall"
printf '%s\n' 4 y | runInstaller
check "tunnel stopped" sh -c '! systemctl is-active --quiet wg-quick@wg0'
check "configuration removed" sh -c '! test -e /etc/wireguard'
check "sysctl file removed" sh -c '! test -e /etc/sysctl.d/wg.conf'
check "unit file removed" sh -c '! test -e /etc/systemd/system/wg-public-ipv4-announce@.service'
check "nft table removed" sh -c '! nft list table inet wireguard >/dev/null 2>&1'
check "no wants symlink left" sh -c '! test -e /etc/systemd/system/wg-quick@wg0.service.wants'
check "proxy_ndp reset" sh -c '[ "$(sysctl -n net.ipv6.conf.all.proxy_ndp)" = 0 ]'
check "no proxy entries left" sh -c '[ -z "$(ip -4 neigh show proxy)" ] && [ -z "$(ip -6 neigh show proxy)" ]'
case "${FIREWALL}" in
ufw) check "ufw rules removed" sh -c '! ufw status | grep -q -E "51820|ALLOW FWD"' ;;
firewalld) check "firewalld rules removed" sh -c '! firewall-cmd --list-ports | grep -q 51820 && ! firewall-cmd --get-policies | grep -q wg-forward' ;;
esac

echo "== install in classic NAT mode"
{
	installAnswers no
	printf '%s\n' erin 10.66.66.2 fd42:42:42::2 1
} | runInstaller
check "classic tunnel active" systemctl is-active --quiet wg-quick@wg0
check "classic NAT rule" sh -c 'nft list table inet wireguard | grep -q "ip saddr 10.66.66.0/24 masquerade"'
check "classic mss clamp" sh -c 'nft list table inet wireguard | grep -q "maxseg size set 1380"'
check "no proxy_ndp in classic mode" sh -c '[ "$(sysctl -n net.ipv6.conf.all.proxy_ndp)" = 0 ]'
check "no announcement unit in classic mode" sh -c '! test -e /etc/systemd/system/wg-public-ipv4-announce@.service'
check "classic client has no hooks" sh -c '! grep -q PostUp /root/wg0-client-erin.conf'

echo "${PASSED} passed, ${FAILED} failed on ${TEST_IMAGE}"
if [[ ${FAILED} -ne 0 ]]; then
	echo "--- last installer output ---" >&2
	tail -60 "${LOG}" >&2
	echo "--- journal ---" >&2
	inside journalctl --no-pager -u 'wg-*' 2>/dev/null | tail -40 >&2 || true
	exit 1
fi
