#!/bin/bash
# Unit tests for the pure functions of wireguard-install.sh.
# Usage: tests/run.sh
set -u

cd "$(dirname "$0")/.." || exit 1
WG_INSTALL_TESTING=1 source ./wireguard-install.sh

PASSED=0
FAILED=0

function pass() {
	PASSED=$((PASSED + 1))
}

function fail() {
	FAILED=$((FAILED + 1))
	echo "FAIL: $*" >&2
}

function assertTrue() {
	# assertTrue <description> <command...>
	local DESCRIPTION=$1
	shift
	if "$@"; then pass; else fail "${DESCRIPTION}: expected success"; fi
}

function assertFalse() {
	local DESCRIPTION=$1
	shift
	if "$@"; then fail "${DESCRIPTION}: expected failure"; else pass; fi
}

function assertEquals() {
	# assertEquals <description> <expected> <actual>
	if [[ $2 == "$3" ]]; then pass; else fail "$1: expected [$2], got [$3]"; fi
}

function assertContains() {
	# assertContains <description> <needle> <haystack>
	if [[ $3 == *"$2"* ]]; then pass; else fail "$1: missing [$2]"; fi
}

function assertNotContains() {
	if [[ $3 == *"$2"* ]]; then fail "$1: unexpected [$2]"; else pass; fi
}

# --- address validation ---
for IP in 1.2.3.4 10.0.0.1 255.255.255.255 0.0.0.0; do
	assertTrue "isValidIpv4 ${IP}" isValidIpv4 "${IP}"
done
for IP in 256.1.1.1 1.2.3 1.2.3.4.5 "" abc 1.2.3.4/32; do
	assertFalse "isValidIpv4 ${IP}" isValidIpv4 "${IP}"
done
for IP in ::1 2001:db8::1 fd42:42:42::2 2001:db8:0:0:0:0:0:1 fe80::; do
	assertTrue "isValidIpv6 ${IP}" isValidIpv6 "${IP}"
done
for IP in 2001:db8::1::2 1.2.3.4 "" 2001:db8:::1 fe80::1%eth0 2001:db8::1/64; do
	assertFalse "isValidIpv6 ${IP}" isValidIpv6 "${IP}"
done
for HOST in vpn.example.com my-host vpn.example.co.uk; do
	assertTrue "isValidHostname ${HOST}" isValidHostname "${HOST}"
done
for HOST in 1.2.3.4 -bad.com bad-.com a..b "" "has space"; do
	assertFalse "isValidHostname ${HOST}" isValidHostname "${HOST}"
done
for IP in 10.1.2.3 172.16.0.1 172.31.255.255 192.168.1.1 100.64.0.1 100.127.255.255 169.254.1.1; do
	assertTrue "isPrivateIpv4 ${IP}" isPrivateIpv4 "${IP}"
done
for IP in 172.32.0.1 100.128.0.1 8.8.8.8 163.5.121.254 11.0.0.1; do
	assertFalse "isPrivateIpv4 ${IP}" isPrivateIpv4 "${IP}"
done

# --- client address lines and modes ---
assertEquals "address line, mixed" "203.0.113.5/32,10.66.66.2/32,2001:db8::5/128,fd42:42:42::2/128" \
	"$(buildClientAddressLine 10.66.66.2 203.0.113.5 fd42:42:42::2 2001:db8::5)"
assertEquals "address line, private v4 only" "10.66.66.2/32" "$(buildClientAddressLine 10.66.66.2 "" "" "")"
assertEquals "address line, public v6 only" "2001:db8::5/128" "$(buildClientAddressLine "" "" "" 2001:db8::5)"
assertEquals "address line, nothing" "" "$(buildClientAddressLine "" "" "" "")"
assertEquals "peer AllowedIPs equals address line" "$(buildClientAddressLine a b c d)" "$(buildPeerAllowedIps a b c d)"

assertTrue "private mode with private v4" validateClientAddressMode private 10.66.66.2 "" "" ""
assertTrue "private mode with private v6 only" validateClientAddressMode private "" "" fd42::2 ""
assertFalse "private mode with a public address" validateClientAddressMode private 10.66.66.2 203.0.113.5 "" ""
assertFalse "private mode with nothing" validateClientAddressMode private "" "" "" ""
assertTrue "public mode with public v4" validateClientAddressMode public "" 203.0.113.5 "" ""
assertFalse "public mode with a private address" validateClientAddressMode public 10.66.66.2 203.0.113.5 "" ""
assertTrue "mixed mode needs both" validateClientAddressMode mixed 10.66.66.2 203.0.113.5 "" ""
assertTrue "mixed mode across families" validateClientAddressMode mixed "" 203.0.113.5 fd42::2 ""
assertFalse "mixed mode with only private" validateClientAddressMode mixed 10.66.66.2 "" "" ""
assertFalse "unknown mode" validateClientAddressMode bogus 10.66.66.2 "" "" ""

# --- client configuration ---
CLIENT=$(buildClientConfig 1420 CPRIV SPUB PSK 198.51.100.1:51820 0.0.0.0/0,::/0 1.1.1.1 1.0.0.1 10.66.66.2 "" fd42:42:42::2 "")
assertContains "private client address" "Address = 10.66.66.2/32,fd42:42:42::2/128" "${CLIENT}"
assertContains "client mtu follows the server" "MTU = 1420" "${CLIENT}"
assertNotContains "clients carry no hooks" "PostUp" "${CLIENT}"
assertContains "client keepalive" "PersistentKeepalive = 15" "${CLIENT}"
assertContains "client endpoint" "Endpoint = 198.51.100.1:51820" "${CLIENT}"
CLIENT=$(buildClientConfig 1380 CPRIV SPUB PSK "[2001:db8::1]:51820" 0.0.0.0/0,::/0 1.1.1.1 1.0.0.1 "" 203.0.113.5 "" "")
assertContains "public client address" "Address = 203.0.113.5/32" "${CLIENT}"
assertContains "bracketed IPv6 endpoint" "Endpoint = [2001:db8::1]:51820" "${CLIENT}"

# --- server peer blocks and extraction ---
PEER_A=$(buildServerPeerBlock alice public KEYA PSKA "" 203.0.113.5 "" 2001:db8::5)
PEER_B=$(buildServerPeerBlock bob private KEYB PSKB 10.66.66.2 "" fd42:42:42::2 "")
PEER_C=$(buildServerPeerBlock carol mixed KEYC PSKC 10.66.66.3 203.0.113.6 "" "")
PEERS="${PEER_A}

${PEER_B}

${PEER_C}"
assertContains "peer header" "### Client alice" "${PEER_A}"
assertContains "peer AllowedIPs" "AllowedIPs = 203.0.113.5/32,2001:db8::5/128" "${PEER_A}"
assertNotContains "no keepalive on the server side" "PersistentKeepalive" "${PEER_A}"
assertEquals "public v4 list" $'203.0.113.5\n203.0.113.6' "$(listPublicAddresses PublicIPv4 "${PEERS}")"
assertEquals "public v6 list" "2001:db8::5" "$(listPublicAddresses PublicIPv6 "${PEERS}")"
assertEquals "removing a peer by name" 2 "$(echo "${PEERS}" | sed "/^### Client alice\$/,/^$/d" | grep -c '^### Client')"

TMP_CONF=$(mktemp)
trap 'rm -f "${TMP_CONF}"' EXIT
printf '[Interface]\nAddress = 10.66.66.1/24\nPostUp = iptables -I INPUT -j ACCEPT\nPostDown = iptables -D INPUT -j ACCEPT\n\n%s\n' "${PEERS}" >"${TMP_CONF}"
assertEquals "peer blocks round-trip" "${PEERS}" "$(getPeerBlocksFromConfig "${TMP_CONF}")"
assertEquals "hooks extraction" $'PostUp = iptables -I INPUT -j ACCEPT\nPostDown = iptables -D INPUT -j ACCEPT' "$(getHooksFromConfig "${TMP_CONF}")"
assertEquals "missing file gives nothing" "" "$(getPeerBlocksFromConfig /nonexistent)"

# --- sysctl ---
SYSCTL=$(buildSysctlConfig yes eth0)
assertContains "forwarding" "net.ipv4.ip_forward = 1" "${SYSCTL}"
assertContains "proxy ndp in public mode" "net.ipv6.conf.all.proxy_ndp = 1" "${SYSCTL}"
assertNotContains "no global proxy arp, entries are per address" "proxy_arp" "${SYSCTL}"
assertContains "accept_ra on the public nic" "net.ipv6.conf.eth0.accept_ra = 2" "${SYSCTL}"
SYSCTL=$(buildSysctlConfig no ens3)
assertNotContains "no proxy ndp in classic mode" "proxy_ndp" "${SYSCTL}"
assertContains "accept_ra follows the nic name" "net.ipv6.conf.ens3.accept_ra = 2" "${SYSCTL}"

# --- nftables ruleset and hooks ---
RULESET=$(buildNftRuleset eth0 wg0 10.66.66.1 fd42:42:42::1 1420)
assertContains "ruleset is idempotent" $'table inet wireguard\ndelete table inet wireguard\ntable inet wireguard {' "${RULESET}"
assertContains "private v4 NAT" 'oifname "eth0" ip saddr 10.66.66.0/24 masquerade' "${RULESET}"
assertContains "private v6 NAT" 'oifname "eth0" ip6 saddr fd42:42:42::/64 masquerade' "${RULESET}"
assertContains "v4 MSS clamp into the tunnel" 'meta nfproto ipv4 oifname "wg0" tcp flags syn tcp option maxseg size > 1380 tcp option maxseg size set 1380' "${RULESET}"
assertContains "v4 MSS clamp out of the tunnel" 'meta nfproto ipv4 iifname "wg0" tcp flags syn tcp option maxseg size > 1380 tcp option maxseg size set 1380' "${RULESET}"
assertContains "v6 MSS clamp" 'meta nfproto ipv6 oifname "wg0" tcp flags syn tcp option maxseg size > 1360 tcp option maxseg size set 1360' "${RULESET}"
assertNotContains "no accept rules of our own" "accept
" "${RULESET//policy accept;/}"
assertContains "MSS follows the MTU" "maxseg size set 1300" "$(buildNftRuleset eth0 wg0 10.66.66.1 fd42:42:42::1 1340)"
if command -v nft &>/dev/null && [[ ${EUID} -eq 0 ]]; then
	# Even the check mode needs netlink access, so this only runs as root
	assertTrue "ruleset parses with nft" nft -c -f <(echo "${RULESET}")
fi

function assertSymmetricHooks() {
	# Every PostUp must have a matching PostDown
	local DESCRIPTION=$1
	local RULES=$2
	local UPS DOWNS
	UPS=$(echo "${RULES}" | sed -n 's/^PostUp = //p' | sed -e 's#nft -f /etc/wireguard/.*#nft delete table inet wireguard#; s/neigh replace proxy/neigh del proxy/' | sort)
	DOWNS=$(echo "${RULES}" | sed -n 's/^PostDown = //p' | sed 's/ || true$//' | sort)
	assertEquals "${DESCRIPTION}: PostUp/PostDown symmetry" "${UPS}" "${DOWNS}"
}

HOOKS=$(buildHookBlock wg0 eth0 $'203.0.113.5\n203.0.113.6' "2001:db8::5")
assertSymmetricHooks "hooks with public addresses" "${HOOKS}"
assertContains "ruleset loaded on PostUp" "PostUp = nft -f /etc/wireguard/wg0.nft" "${HOOKS}"
assertContains "ruleset removed on PostDown" "PostDown = nft delete table inet wireguard || true" "${HOOKS}"
assertContains "arp proxy" "PostUp = ip -4 neigh replace proxy 203.0.113.6 dev eth0" "${HOOKS}"
assertContains "ndp proxy" "PostUp = ip -6 neigh replace proxy 2001:db8::5 dev eth0" "${HOOKS}"
assertContains "proxy removal tolerates absence" "PostDown = ip -6 neigh del proxy 2001:db8::5 dev eth0 || true" "${HOOKS}"
assertEquals "hooks without public addresses" 2 "$(buildHookBlock wg0 eth0 "" "" | wc -l)"
printf '[Interface]\n%s\n' "${HOOKS}" >"${TMP_CONF}"
assertEquals "proxy entries extracted" $'-4 203.0.113.5 dev eth0\n-4 203.0.113.6 dev eth0\n-6 2001:db8::5 dev eth0' "$(listProxyEntries "${TMP_CONF}")"

# --- announcement service ---
ENV_FILE=$(buildAnnouncementEnvironment eth0 "203.0.113.5 203.0.113.6")
assertContains "env nic" "SERVER_PUB_NIC=eth0" "${ENV_FILE}"
assertContains "env list is quoted" 'PUBLIC_IPV4_LIST="203.0.113.5 203.0.113.6"' "${ENV_FILE}"
UNIT=$(buildAnnouncementSystemdUnit /usr/bin/python3)
assertContains "unit bound to the tunnel" "BindsTo=wg-quick@%i.service" "${UNIT}"
assertContains "unit wanted by the tunnel" "WantedBy=wg-quick@%i.service" "${UNIT}"
assertContains "unit env file" "EnvironmentFile=/etc/wireguard/public-ipv4-announce-%i.env" "${UNIT}"
assertContains "unit runs the python sender" "ExecStart=/usr/bin/python3 /etc/wireguard/wg-public-ipv4-announce.py" "${UNIT}"
assertContains "unit capabilities" "CapabilityBoundingSet=CAP_NET_RAW" "${UNIT}"
assertContains "unit has no start rate limit" "StartLimitIntervalSec=0" "${UNIT}"
SCRIPT=$(buildAnnouncementScript)
if command -v python3 &>/dev/null; then
	assertTrue "announcement script compiles" python3 -c 'import sys; compile(sys.stdin.read(), "announce.py", "exec")' <<<"${SCRIPT}"
	FRAME=$(
		python3 - <<PYTHON
import socket, struct
${SCRIPT//if __name__ == \"__main__\":*/}
frame = arp_frame(2, bytes.fromhex("0a0b0c0d0e0f"), socket.inet_aton("203.0.113.5"))
print(len(frame), frame[:6].hex(), frame[12:14].hex(), struct.unpack("!H", frame[20:22])[0], socket.inet_ntoa(frame[28:32]), socket.inet_ntoa(frame[38:42]))
PYTHON
	)
	assertEquals "gratuitous reply frame layout" "42 ffffffffffff 0806 2 203.0.113.5 203.0.113.5" "${FRAME}"
fi
if command -v systemd-analyze &>/dev/null; then
	UNIT_DIR=$(mktemp -d)
	echo "${UNIT}" >"${UNIT_DIR}/wg-public-ipv4-announce@.service"
	# The verifier complains about missing files, not about syntax, so only syntax errors count
	VERIFY=$(systemd-analyze verify --man=no "${UNIT_DIR}/wg-public-ipv4-announce@wg0.service" 2>&1 | grep -v -E 'not executable|Failed to open|not found|Permission' || true)
	assertEquals "unit passes systemd-analyze verify" "" "${VERIFY}"
	rm -rf "${UNIT_DIR}"
fi

echo "${PASSED} passed, ${FAILED} failed"
[[ ${FAILED} -eq 0 ]]
