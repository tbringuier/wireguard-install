#!/bin/bash

# WireGuard server installer with public IP routing
# https://github.com/tbringuier/wireguard-install
#
# Fork of https://github.com/angristan/wireguard-install (MIT licence).
# Requires systemd. Tested on Debian, Ubuntu, Fedora, Rocky/Alma, Arch, openSUSE and Flatcar.

RED='\033[0;31m'
ORANGE='\033[0;33m'
GREEN='\033[0;32m'
NC='\033[0m'

function buildClientAddressLine() {
	local PRIVATE_IPV4=$1
	local PUBLIC_IPV4=$2
	local PRIVATE_IPV6=$3
	local PUBLIC_IPV6=$4
	local ADDRESSES=""
	local ADDRESS

	for ADDRESS in \
		"${PUBLIC_IPV4:+${PUBLIC_IPV4}/32}" \
		"${PRIVATE_IPV4:+${PRIVATE_IPV4}/32}" \
		"${PUBLIC_IPV6:+${PUBLIC_IPV6}/128}" \
		"${PRIVATE_IPV6:+${PRIVATE_IPV6}/128}"; do
		if [[ -z ${ADDRESS} ]]; then
			continue
		elif [[ -z ${ADDRESSES} ]]; then
			ADDRESSES=${ADDRESS}
		else
			ADDRESSES="${ADDRESSES},${ADDRESS}"
		fi
	done

	echo "${ADDRESSES}"
}

function validateClientAddressMode() {
	local CLIENT_ADDRESS_MODE=$1
	local PRIVATE_IPV4=$2
	local PUBLIC_IPV4=$3
	local PRIVATE_IPV6=$4
	local PUBLIC_IPV6=$5

	case "${CLIENT_ADDRESS_MODE}" in
	private)
		[[ (-n ${PRIVATE_IPV4} || -n ${PRIVATE_IPV6}) && -z ${PUBLIC_IPV4} && -z ${PUBLIC_IPV6} ]]
		;;
	public)
		[[ (-n ${PUBLIC_IPV4} || -n ${PUBLIC_IPV6}) && -z ${PRIVATE_IPV4} && -z ${PRIVATE_IPV6} ]]
		;;
	mixed)
		[[ (-n ${PRIVATE_IPV4} || -n ${PRIVATE_IPV6}) && (-n ${PUBLIC_IPV4} || -n ${PUBLIC_IPV6}) ]]
		;;
	*)
		return 1
		;;
	esac
}

function buildPeerAllowedIps() {
	local PRIVATE_IPV4=$1
	local PUBLIC_IPV4=$2
	local PRIVATE_IPV6=$3
	local PUBLIC_IPV6=$4

	buildClientAddressLine "${PRIVATE_IPV4}" "${PUBLIC_IPV4}" "${PRIVATE_IPV6}" "${PUBLIC_IPV6}"
}

function buildClientHookBlock() {
	local CLIENT_ADDRESS_MODE=$1
	local WG_INTERFACE=$2

	if [[ ${CLIENT_ADDRESS_MODE} == "public" ]] || [[ ${CLIENT_ADDRESS_MODE} == "mixed" ]]; then
		echo "PostUp = iptables -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -o ${WG_INTERFACE} -j TCPMSS --clamp-mss-to-pmtu
PostDown = iptables -t mangle -D POSTROUTING -p tcp --tcp-flags SYN,RST SYN -o ${WG_INTERFACE} -j TCPMSS --clamp-mss-to-pmtu"
	fi
}

function validatePublicRoutingEnvironment() {
	local PUBLIC_ROUTING_MODE=$1
	local FIREWALLD_ACTIVE=$2

	if [[ ${PUBLIC_ROUTING_MODE} == "yes" ]] && [[ ${FIREWALLD_ACTIVE} == "yes" ]]; then
		echo "Public routing mode requires iptables/ip6tables and cannot be enabled while firewalld is active."
		return 1
	fi
}

function selectFirewallBackend() {
	local PUBLIC_ROUTING_MODE=$1
	local FIREWALLD_ACTIVE=$2

	if [[ ${PUBLIC_ROUTING_MODE} == "yes" ]]; then
		echo "public-routing"
	elif [[ ${FIREWALLD_ACTIVE} == "yes" ]]; then
		echo "firewalld"
	else
		echo "iptables"
	fi
}

function validatePublicRoutingDependencies() {
	local PUBLIC_ROUTING_MODE=$1
	local ARPING_AVAILABLE=$2

	if [[ ${PUBLIC_ROUTING_MODE} == "yes" ]] && [[ ${ARPING_AVAILABLE} != "yes" ]]; then
		echo "Public routing mode requires the arping command, but it is not available."
		return 1
	fi
}

function buildSysctlConfig() {
	local PUBLIC_ROUTING_MODE=$1

	if [[ ${PUBLIC_ROUTING_MODE} == "yes" ]]; then
		echo "net.ipv4.ip_forward = 1
net.ipv4.conf.all.proxy_arp = 1
net.ipv6.conf.all.forwarding = 1"
	else
		echo "net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1"
	fi
}

function buildManagedRuleBlock() {
	local SERVER_PORT=$1
	local SERVER_PUB_NIC=$2
	local SERVER_WG_NIC=$3
	local SERVER_WG_IPV4=$4
	local SERVER_WG_IPV6=$5
	local PUBLIC_IPV4_LIST=$6
	local PUBLIC_IPV6_LIST=$7
	local PRIVATE_IPV4_CIDR
	local PRIVATE_IPV6_CIDR
	local RULES
	local PUBLIC_IPV4
	local PUBLIC_IPV6

	PRIVATE_IPV4_CIDR=$(echo "${SERVER_WG_IPV4}" | awk -F '.' '{ print $1 "." $2 "." $3 ".0/24" }')
	PRIVATE_IPV6_CIDR="$(echo "${SERVER_WG_IPV6}" | awk -F '::' '{ print $1 }')::/64"

	RULES="PostUp = iptables -I INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
PostUp = iptables -I FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_WG_NIC} -d ${PRIVATE_IPV4_CIDR} -j ACCEPT
PostUp = iptables -I FORWARD -i ${SERVER_WG_NIC} -s ${PRIVATE_IPV4_CIDR} -j ACCEPT
PostUp = iptables -t nat -A POSTROUTING -o ${SERVER_PUB_NIC} -s ${PRIVATE_IPV4_CIDR} -j MASQUERADE
PostUp = ip6tables -I FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_WG_NIC} -d ${PRIVATE_IPV6_CIDR} -j ACCEPT
PostUp = ip6tables -I FORWARD -i ${SERVER_WG_NIC} -s ${PRIVATE_IPV6_CIDR} -j ACCEPT
PostUp = ip6tables -t nat -A POSTROUTING -o ${SERVER_PUB_NIC} -s ${PRIVATE_IPV6_CIDR} -j MASQUERADE
PostDown = iptables -D INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
PostDown = iptables -D FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_WG_NIC} -d ${PRIVATE_IPV4_CIDR} -j ACCEPT
PostDown = iptables -D FORWARD -i ${SERVER_WG_NIC} -s ${PRIVATE_IPV4_CIDR} -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -s ${PRIVATE_IPV4_CIDR} -j MASQUERADE
PostDown = ip6tables -D FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_WG_NIC} -d ${PRIVATE_IPV6_CIDR} -j ACCEPT
PostDown = ip6tables -D FORWARD -i ${SERVER_WG_NIC} -s ${PRIVATE_IPV6_CIDR} -j ACCEPT
PostDown = ip6tables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -s ${PRIVATE_IPV6_CIDR} -j MASQUERADE"

	while IFS= read -r PUBLIC_IPV4; do
		[[ -n ${PUBLIC_IPV4} ]] || continue
		RULES="${RULES}
PostUp = iptables -I FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_WG_NIC} -d ${PUBLIC_IPV4}/32 -j ACCEPT
PostUp = iptables -I FORWARD -i ${SERVER_WG_NIC} -s ${PUBLIC_IPV4}/32 -j ACCEPT
PostDown = iptables -D FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_WG_NIC} -d ${PUBLIC_IPV4}/32 -j ACCEPT
PostDown = iptables -D FORWARD -i ${SERVER_WG_NIC} -s ${PUBLIC_IPV4}/32 -j ACCEPT"
	done <<<"${PUBLIC_IPV4_LIST}"

	while IFS= read -r PUBLIC_IPV6; do
		[[ -n ${PUBLIC_IPV6} ]] || continue
		RULES="${RULES}
PostUp = ip6tables -I FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_WG_NIC} -d ${PUBLIC_IPV6}/128 -j ACCEPT
PostUp = ip6tables -I FORWARD -i ${SERVER_WG_NIC} -s ${PUBLIC_IPV6}/128 -j ACCEPT
PostDown = ip6tables -D FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_WG_NIC} -d ${PUBLIC_IPV6}/128 -j ACCEPT
PostDown = ip6tables -D FORWARD -i ${SERVER_WG_NIC} -s ${PUBLIC_IPV6}/128 -j ACCEPT"
	done <<<"${PUBLIC_IPV6_LIST}"

	echo "${RULES}"
}

function buildClientConfig() {
	local CLIENT_ADDRESS_MODE=$1
	local WG_INTERFACE=$2
	local CLIENT_PRIV_KEY=$3
	local SERVER_PUB_KEY=$4
	local CLIENT_PRE_SHARED_KEY=$5
	local ENDPOINT=$6
	local ALLOWED_IPS=$7
	local CLIENT_DNS_1=$8
	local CLIENT_DNS_2=$9
	local PRIVATE_IPV4=${10}
	local PUBLIC_IPV4=${11}
	local PRIVATE_IPV6=${12}
	local PUBLIC_IPV6=${13}
	local ADDRESS_LINE
	local HOOK_BLOCK

	ADDRESS_LINE=$(buildClientAddressLine "${PRIVATE_IPV4}" "${PUBLIC_IPV4}" "${PRIVATE_IPV6}" "${PUBLIC_IPV6}")
	HOOK_BLOCK=$(buildClientHookBlock "${CLIENT_ADDRESS_MODE}" "${WG_INTERFACE}")

	echo "[Interface]
PrivateKey = ${CLIENT_PRIV_KEY}
Address = ${ADDRESS_LINE}
DNS = ${CLIENT_DNS_1},${CLIENT_DNS_2}
${HOOK_BLOCK}

# Uncomment the next line to set a custom MTU
# This might impact performance, so use it only if you know what you are doing
# See https://github.com/nitred/nr-wg-mtu-finder to find your optimal MTU
# MTU = 1420

[Peer]
PublicKey = ${SERVER_PUB_KEY}
PresharedKey = ${CLIENT_PRE_SHARED_KEY}
Endpoint = ${ENDPOINT}
AllowedIPs = ${ALLOWED_IPS}
PersistentKeepalive = 15"
}

function buildServerPeerBlock() {
	local CLIENT_NAME=$1
	local CLIENT_ADDRESS_MODE=$2
	local CLIENT_PUB_KEY=$3
	local CLIENT_PRE_SHARED_KEY=$4
	local PRIVATE_IPV4=$5
	local PUBLIC_IPV4=$6
	local PRIVATE_IPV6=$7
	local PUBLIC_IPV6=$8

	echo "### Client ${CLIENT_NAME}
# AddressMode: ${CLIENT_ADDRESS_MODE}
# PrivateIPv4: ${PRIVATE_IPV4}
# PublicIPv4: ${PUBLIC_IPV4}
# PrivateIPv6: ${PRIVATE_IPV6}
# PublicIPv6: ${PUBLIC_IPV6}
[Peer]
PublicKey = ${CLIENT_PUB_KEY}
PresharedKey = ${CLIENT_PRE_SHARED_KEY}
AllowedIPs = $(buildPeerAllowedIps "${PRIVATE_IPV4}" "${PUBLIC_IPV4}" "${PRIVATE_IPV6}" "${PUBLIC_IPV6}")
PersistentKeepalive = 15"
}

function listPublicIpv4FromConfig() {
	local WG_CONF_FILE=$1

	if [[ -e ${WG_CONF_FILE} ]]; then
		awk -F ': ' '/^# PublicIPv4: / && $2 != "" { print $2 }' "${WG_CONF_FILE}"
	fi
}

function listPublicIpv6FromConfig() {
	local WG_CONF_FILE=$1

	if [[ -e ${WG_CONF_FILE} ]]; then
		awk -F ': ' '/^# PublicIPv6: / && $2 != "" { print $2 }' "${WG_CONF_FILE}"
	fi
}

function getPeerBlocksFromConfig() {
	local WG_CONF_FILE=$1

	if [[ -e ${WG_CONF_FILE} ]]; then
		awk 'BEGIN { printing = 0 } /^### Client / { printing = 1 } printing { print }' "${WG_CONF_FILE}"
	fi
}

function buildClassicFirewalldRuleBlock() {
	local SERVER_PORT=$1
	local SERVER_WG_NIC=$2
	local SERVER_WG_IPV4=$3
	local SERVER_WG_IPV6=$4
	local FIREWALLD_IPV4_ADDRESS
	local FIREWALLD_IPV6_ADDRESS

	FIREWALLD_IPV4_ADDRESS=$(echo "${SERVER_WG_IPV4}" | cut -d"." -f1-3)".0"
	FIREWALLD_IPV6_ADDRESS=$(echo "${SERVER_WG_IPV6}" | sed 's/:[^:]*$/:0/')

	echo "PostUp = firewall-cmd --zone=public --add-interface=${SERVER_WG_NIC} && firewall-cmd --add-port ${SERVER_PORT}/udp && firewall-cmd --add-rich-rule='rule family=ipv4 source address=${FIREWALLD_IPV4_ADDRESS}/24 masquerade' && firewall-cmd --add-rich-rule='rule family=ipv6 source address=${FIREWALLD_IPV6_ADDRESS}/24 masquerade'
PostDown = firewall-cmd --zone=public --add-interface=${SERVER_WG_NIC} && firewall-cmd --remove-port ${SERVER_PORT}/udp && firewall-cmd --remove-rich-rule='rule family=ipv4 source address=${FIREWALLD_IPV4_ADDRESS}/24 masquerade' && firewall-cmd --remove-rich-rule='rule family=ipv6 source address=${FIREWALLD_IPV6_ADDRESS}/24 masquerade'"
}

function buildClassicIptablesRuleBlock() {
	local SERVER_PORT=$1
	local SERVER_PUB_NIC=$2
	local SERVER_WG_NIC=$3

	echo "PostUp = iptables -I INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
PostUp = iptables -I FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_WG_NIC} -j ACCEPT
PostUp = iptables -I FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
PostUp = iptables -t nat -A POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostUp = ip6tables -I FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
PostUp = ip6tables -t nat -A POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostDown = iptables -D INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
PostDown = iptables -D FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_WG_NIC} -j ACCEPT
PostDown = iptables -D FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostDown = ip6tables -D FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
PostDown = ip6tables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE"
}

function writeServerConfig() {
	local WG_CONF_FILE=$1
	local PEER_BLOCKS=$2
	local PUBLIC_IPV4_LIST=$3
	local PUBLIC_IPV6_LIST=$4
	local RULE_BLOCK

	if [[ ${FIREWALL_BACKEND} == 'public-routing' ]]; then
		RULE_BLOCK=$(buildManagedRuleBlock \
			"${SERVER_PORT}" \
			"${SERVER_PUB_NIC}" \
			"${SERVER_WG_NIC}" \
			"${SERVER_WG_IPV4}" \
			"${SERVER_WG_IPV6}" \
			"${PUBLIC_IPV4_LIST}" \
			"${PUBLIC_IPV6_LIST}")
	elif [[ ${FIREWALL_BACKEND} == 'firewalld' ]]; then
		RULE_BLOCK=$(buildClassicFirewalldRuleBlock \
			"${SERVER_PORT}" \
			"${SERVER_WG_NIC}" \
			"${SERVER_WG_IPV4}" \
			"${SERVER_WG_IPV6}")
	else
		RULE_BLOCK=$(buildClassicIptablesRuleBlock \
			"${SERVER_PORT}" \
			"${SERVER_PUB_NIC}" \
			"${SERVER_WG_NIC}")
	fi

	printf '[Interface]\nAddress = %s/24,%s/64\nListenPort = %s\nPrivateKey = %s\n' \
		"${SERVER_WG_IPV4}" \
		"${SERVER_WG_IPV6}" \
		"${SERVER_PORT}" \
		"${SERVER_PRIV_KEY}" >"${WG_CONF_FILE}"
	printf '%s\n' "${RULE_BLOCK}" >>"${WG_CONF_FILE}"

	if [[ -n ${PEER_BLOCKS} ]]; then
		printf '\n%s\n' "${PEER_BLOCKS}" >>"${WG_CONF_FILE}"
	fi
}

function rebuildPublicIpv4Inventory() {
	local WG_CONF_FILE=$1
	local INVENTORY_FILE=$2

	listPublicIpv4FromConfig "${WG_CONF_FILE}" >"${INVENTORY_FILE}"
}

function buildArpingLoopScript() {
	echo '#!/bin/bash
set -euo pipefail

PARAMS_FILE="/etc/wireguard/params"
INVENTORY_FILE="/etc/wireguard/public-ipv4.list"

source "${PARAMS_FILE}"

while true; do
	if [[ -s ${INVENTORY_FILE} ]]; then
		while IFS= read -r PUBLIC_IPV4; do
			[[ -n ${PUBLIC_IPV4} ]] || continue
			arping -q -c1 -P "${PUBLIC_IPV4}" -S "${PUBLIC_IPV4}" -I "${SERVER_PUB_NIC}" || true
		done <"${INVENTORY_FILE}"
	fi
	sleep 1
done'
}

function buildArpingSystemdService() {
	echo '[Unit]
Description=WireGuard public IPv4 announcement loop
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart=/etc/wireguard/wg-public-ipv4-arping.sh
Restart=always
RestartSec=1

[Install]
WantedBy=multi-user.target'
}

function refreshPublicIpv4AnnouncementService() {
	local WG_CONF_FILE="/etc/wireguard/${SERVER_WG_NIC}.conf"

	if [[ ${PUBLIC_ROUTING_MODE} != 'yes' ]]; then
		return
	fi

	rebuildPublicIpv4Inventory "${WG_CONF_FILE}" "/etc/wireguard/public-ipv4.list"
	printf '%s\n' "$(buildArpingLoopScript)" >/etc/wireguard/wg-public-ipv4-arping.sh
	chmod +x /etc/wireguard/wg-public-ipv4-arping.sh

	printf '%s\n' "$(buildArpingSystemdService)" >/etc/systemd/system/wg-public-ipv4-arping.service
	systemctl daemon-reload
	systemctl enable wg-public-ipv4-arping >/dev/null 2>&1
	systemctl restart wg-public-ipv4-arping >/dev/null 2>&1 || systemctl start wg-public-ipv4-arping >/dev/null 2>&1
}

function removePublicIpv4AnnouncementService() {
	if [[ ${PUBLIC_ROUTING_MODE} != 'yes' ]]; then
		return
	fi

	systemctl stop wg-public-ipv4-arping >/dev/null 2>&1 || true
	systemctl disable wg-public-ipv4-arping >/dev/null 2>&1 || true
	rm -f /etc/systemd/system/wg-public-ipv4-arping.service
	systemctl daemon-reload

	rm -f /etc/wireguard/wg-public-ipv4-arping.sh
	rm -f /etc/wireguard/public-ipv4.list
}

function applyWireGuardConfig() {
	if [[ ${PUBLIC_ROUTING_MODE} == 'yes' ]]; then
		systemctl restart "wg-quick@${SERVER_WG_NIC}"
	else
		wg syncconf "${SERVER_WG_NIC}" <(wg-quick strip "${SERVER_WG_NIC}")
	fi
}

function installPackages() {
	if ! "$@"; then
		echo -e "${RED}Failed to install packages.${NC}"
		echo "Please check your internet connection and package sources."
		exit 1
	fi
}

function installOptionalPackages() {
	if ! "$@"; then
		echo -e "${ORANGE}Optional packages could not be installed, continuing without them.${NC}"
	fi
}

function isRoot() {
	if [ "${EUID}" -ne 0 ]; then
		echo "You need to run this script as root"
		exit 1
	fi
}

function checkSystemd() {
	if [[ ! -d /run/systemd/system ]] || ! command -v systemctl &>/dev/null; then
		echo "This script requires systemd as the init system."
		exit 1
	fi
}

function waitForCloudInit() {
	# On a freshly provisioned cloud instance, cloud-init may still be configuring
	# the network or running package updates. Wait for it before touching anything.
	if command -v cloud-init &>/dev/null && [[ -d /run/cloud-init ]]; then
		if ! cloud-init status >/dev/null 2>&1; then
			return
		fi
		if [[ $(cloud-init status 2>/dev/null) == *running* ]]; then
			echo "Waiting for cloud-init to finish..."
			cloud-init status --wait >/dev/null 2>&1 || true
		fi
	fi
}

function checkVirt() {
	VIRT=$(systemd-detect-virt)
	if [[ ${VIRT} == "openvz" ]]; then
		echo "OpenVZ is not supported"
		exit 1
	fi
	if [[ ${VIRT} == "lxc" ]]; then
		echo "LXC is not supported (yet)."
		echo "WireGuard can technically run in an LXC container,"
		echo "but the kernel module has to be installed on the host,"
		echo "the container has to be run with some specific parameters"
		echo "and only the tools need to be installed in the container."
		exit 1
	fi
}

function checkOS() {
	if [[ ! -e /etc/os-release ]]; then
		echo "Unable to detect the distribution: /etc/os-release is missing."
		exit 1
	fi
	source /etc/os-release
	OS="${ID}"
	OS_FAMILY=""

	# Map the distribution (or the ones it derives from) to a package family
	local CANDIDATE
	for CANDIDATE in ${ID} ${ID_LIKE:-}; do
		case "${CANDIDATE}" in
		debian | ubuntu | raspbian)
			OS_FAMILY=debian
			;;
		fedora | rhel | centos | almalinux | rocky | ol)
			OS_FAMILY=rhel
			;;
		arch | archarm | manjaro)
			OS_FAMILY=arch
			;;
		suse | opensuse | opensuse-leap | opensuse-tumbleweed | sles)
			OS_FAMILY=suse
			;;
		flatcar)
			OS_FAMILY=flatcar
			;;
		*)
			continue
			;;
		esac
		break
	done

	# Unknown distribution: fall back on the package manager that is available
	if [[ -z ${OS_FAMILY} ]]; then
		if command -v apt-get &>/dev/null; then
			OS_FAMILY=debian
		elif command -v dnf &>/dev/null; then
			OS_FAMILY=rhel
		elif command -v pacman &>/dev/null; then
			OS_FAMILY=arch
		elif command -v zypper &>/dev/null; then
			OS_FAMILY=suse
		else
			echo "Looks like you aren't running this installer on a supported system (${PRETTY_NAME:-${ID}})."
			echo "Supported package managers: apt-get, dnf, pacman, zypper. Flatcar Linux is supported as-is."
			exit 1
		fi
	fi

	# Reject releases whose kernel or repositories predate WireGuard
	local MAJOR_VERSION="${VERSION_ID%%.*}"
	if [[ -n ${MAJOR_VERSION} && ${MAJOR_VERSION} =~ ^[0-9]+$ ]]; then
		case "${OS}" in
		debian | raspbian)
			if [[ ${MAJOR_VERSION} -lt 11 ]]; then
				echo "Your version of Debian (${VERSION_ID}) is not supported. Please use Debian 11 Bullseye or later"
				exit 1
			fi
			;;
		ubuntu)
			if [[ ${MAJOR_VERSION} -lt 20 ]]; then
				echo "Your version of Ubuntu (${VERSION_ID}) is not supported. Please use Ubuntu 20.04 or later"
				exit 1
			fi
			;;
		fedora)
			if [[ ${MAJOR_VERSION} -lt 32 ]]; then
				echo "Your version of Fedora (${VERSION_ID}) is not supported. Please use Fedora 32 or later"
				exit 1
			fi
			;;
		centos | almalinux | rocky | rhel | ol)
			if [[ ${MAJOR_VERSION} -lt 8 ]]; then
				echo "Your version of ${PRETTY_NAME:-${ID}} is not supported. Please use release 8 or later"
				exit 1
			fi
			;;
		esac
	fi
}

function getHomeDirForClient() {
	local CLIENT_NAME=$1

	if [ -z "${CLIENT_NAME}" ]; then
		echo "Error: getHomeDirForClient() requires a client name as argument"
		exit 1
	fi

	# Home directory of the user, where the client configuration will be written
	if [ -e "/home/${CLIENT_NAME}" ]; then
		# if $1 is a user name
		HOME_DIR="/home/${CLIENT_NAME}"
	elif [ "${SUDO_USER}" ]; then
		# if not, use SUDO_USER
		if [ "${SUDO_USER}" == "root" ]; then
			# If running sudo as root
			HOME_DIR="/root"
		else
			HOME_DIR="/home/${SUDO_USER}"
		fi
	else
		# if not SUDO_USER, use /root
		HOME_DIR="/root"
	fi

	echo "$HOME_DIR"
}

function initialCheck() {
	isRoot
	checkSystemd
	checkOS
	checkVirt
	waitForCloudInit
}

function installQuestions() {
	echo "Welcome to the WireGuard installer!"
	echo "The git repository is available at: https://github.com/tbringuier/wireguard-install"
	echo ""
	echo "I need to ask you a few questions before starting the setup."
	echo "You can keep the default options and just press enter if you are ok with them."
	echo ""

	# Detect public IPv4 or IPv6 address and pre-fill for the user
	SERVER_PUB_IP=$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | awk '{print $1}' | head -1)
	if [[ -z ${SERVER_PUB_IP} ]]; then
		# Detect public IPv6 address
		SERVER_PUB_IP=$(ip -6 addr | sed -ne 's|^.* inet6 \([^/]*\)/.* scope global.*$|\1|p' | head -1)
	fi
	read -rp "IPv4 or IPv6 public address: " -e -i "${SERVER_PUB_IP}" SERVER_PUB_IP

	# Detect public interface and pre-fill for the user
	SERVER_NIC="$(ip -4 route ls | grep default | awk '/dev/ {for (i=1; i<=NF; i++) if ($i == "dev") print $(i+1)}' | head -1)"
	until [[ ${SERVER_PUB_NIC} =~ ^[a-zA-Z0-9_]+$ ]]; do
		read -rp "Public interface: " -e -i "${SERVER_NIC}" SERVER_PUB_NIC
	done

	until [[ ${SERVER_WG_NIC} =~ ^[a-zA-Z0-9_]+$ && ${#SERVER_WG_NIC} -lt 16 ]]; do
		read -rp "WireGuard interface name: " -e -i wg0 SERVER_WG_NIC
	done

	until [[ ${SERVER_WG_IPV4} =~ ^([0-9]{1,3}\.){3} ]]; do
		read -rp "Server WireGuard IPv4: " -e -i 10.66.66.1 SERVER_WG_IPV4
	done

	until [[ ${SERVER_WG_IPV6} =~ ^([a-f0-9]{1,4}:){3,4}: ]]; do
		read -rp "Server WireGuard IPv6: " -e -i fd42:42:42::1 SERVER_WG_IPV6
	done

	# Generate random number within private ports range
	RANDOM_PORT=$(shuf -i49152-65535 -n1)
	until [[ ${SERVER_PORT} =~ ^[0-9]+$ ]] && [ "${SERVER_PORT}" -ge 1 ] && [ "${SERVER_PORT}" -le 65535 ]; do
		read -rp "Server WireGuard port [1-65535]: " -e -i "${RANDOM_PORT}" SERVER_PORT
	done

	# Cloudflare DNS by default
	until [[ ${CLIENT_DNS_1} =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
		read -rp "First DNS resolver to use for the clients: " -e -i 1.1.1.1 CLIENT_DNS_1
	done
	until [[ ${CLIENT_DNS_2} =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
		read -rp "Second DNS resolver to use for the clients (optional): " -e -i 1.0.0.1 CLIENT_DNS_2
		if [[ ${CLIENT_DNS_2} == "" ]]; then
			CLIENT_DNS_2="${CLIENT_DNS_1}"
		fi
	done

	until [[ ${PUBLIC_ROUTING_MODE} =~ ^(yes|no)$ ]]; do
		read -rp "Enable public IP routing support [yes/no]: " -e -i no PUBLIC_ROUTING_MODE
	done

	if systemctl is-active --quiet firewalld; then
		FIREWALLD_ACTIVE=yes
	else
		FIREWALLD_ACTIVE=no
	fi
	validatePublicRoutingEnvironment "${PUBLIC_ROUTING_MODE}" "${FIREWALLD_ACTIVE}" || exit 1
	FIREWALL_BACKEND=$(selectFirewallBackend "${PUBLIC_ROUTING_MODE}" "${FIREWALLD_ACTIVE}")

	until [[ ${ALLOWED_IPS} =~ ^.+$ ]]; do
		echo -e "\nWireGuard uses a parameter called AllowedIPs to determine what is routed over the VPN."
		read -rp "Allowed IPs list for generated clients (leave default to route everything): " -e -i '0.0.0.0/0,::/0' ALLOWED_IPS
		if [[ ${ALLOWED_IPS} == "" ]]; then
			ALLOWED_IPS="0.0.0.0/0,::/0"
		fi
	done

	echo ""
	echo "Okay, that was all I needed. We are ready to setup your WireGuard server now."
	echo "You will be able to generate a client at the end of the installation."
	read -n1 -r -p "Press any key to continue..."
}

function installWireGuard() {
	# Run setup questions first
	installQuestions

	# Install WireGuard tools and module
	case "${OS_FAMILY}" in
	debian)
		export DEBIAN_FRONTEND=noninteractive
		# Wait for the dpkg lock: cloud-init or unattended-upgrades may hold it after boot
		local APT_GET=(apt-get -o DPkg::Lock::Timeout=300)
		"${APT_GET[@]}" update
		installPackages "${APT_GET[@]}" install -y wireguard iptables
		installOptionalPackages "${APT_GET[@]}" install -y qrencode
		if [[ ${PUBLIC_ROUTING_MODE} == 'yes' ]]; then
			installPackages "${APT_GET[@]}" install -y iputils-arping
		fi
		;;
	rhel)
		if [[ ${OS} == 'ol' && ${VERSION_ID%%.*} == 8 ]]; then
			# Oracle Linux 8 ships wireguard-tools in the UEK R6 developer repository
			installPackages dnf install -y oraclelinux-developer-release-el8
			dnf config-manager --disable -y ol8_developer
			dnf config-manager --enable -y ol8_developer_UEKR6
			dnf config-manager --save -y --setopt=ol8_developer_UEKR6.includepkgs='wireguard-tools*'
		elif [[ ${OS} != 'fedora' && ${VERSION_ID%%.*} == 8 ]]; then
			# The EL8 kernel predates WireGuard: use the ELRepo kernel module
			installOptionalPackages dnf install -y epel-release elrepo-release
			installPackages dnf install -y kmod-wireguard
		elif [[ ${OS} != 'fedora' ]]; then
			# qrencode lives in EPEL on Enterprise Linux
			installOptionalPackages dnf install -y epel-release
		fi
		installPackages dnf install -y wireguard-tools iptables
		installOptionalPackages dnf install -y qrencode
		if [[ ${PUBLIC_ROUTING_MODE} == 'yes' ]]; then
			installPackages dnf install -y iputils
		fi
		;;
	arch)
		installPackages pacman -S --needed --noconfirm wireguard-tools
		if ! command -v iptables &>/dev/null; then
			installPackages pacman -S --needed --noconfirm iptables
		fi
		installOptionalPackages pacman -S --needed --noconfirm qrencode
		if [[ ${PUBLIC_ROUTING_MODE} == 'yes' ]]; then
			installPackages pacman -S --needed --noconfirm iputils
		fi
		;;
	suse)
		installPackages zypper --non-interactive install wireguard-tools iptables
		installOptionalPackages zypper --non-interactive install qrencode
		if [[ ${PUBLIC_ROUTING_MODE} == 'yes' ]]; then
			installPackages zypper --non-interactive install iputils
		fi
		;;
	flatcar)
		# Flatcar ships WireGuard, iptables and iputils in its read-only /usr
		;;
	esac

	# Verify WireGuard installation
	if ! command -v wg &>/dev/null; then
		echo -e "${RED}WireGuard installation failed. The 'wg' command was not found.${NC}"
		echo "Please check the installation output above for errors."
		exit 1
	fi

	if command -v arping &>/dev/null; then
		validatePublicRoutingDependencies "${PUBLIC_ROUTING_MODE}" "yes" || exit 1
	else
		validatePublicRoutingDependencies "${PUBLIC_ROUTING_MODE}" "no" || exit 1
	fi

	# Make sure the directory exists with restrictive permissions
	install -d -m 700 /etc/wireguard

	SERVER_PRIV_KEY=$(wg genkey)
	SERVER_PUB_KEY=$(echo "${SERVER_PRIV_KEY}" | wg pubkey)

	# Save WireGuard settings
	echo "SERVER_PUB_IP=${SERVER_PUB_IP}
SERVER_PUB_NIC=${SERVER_PUB_NIC}
SERVER_WG_NIC=${SERVER_WG_NIC}
SERVER_WG_IPV4=${SERVER_WG_IPV4}
SERVER_WG_IPV6=${SERVER_WG_IPV6}
SERVER_PORT=${SERVER_PORT}
SERVER_PRIV_KEY=${SERVER_PRIV_KEY}
SERVER_PUB_KEY=${SERVER_PUB_KEY}
CLIENT_DNS_1=${CLIENT_DNS_1}
CLIENT_DNS_2=${CLIENT_DNS_2}
ALLOWED_IPS=${ALLOWED_IPS}
PUBLIC_ROUTING_MODE=${PUBLIC_ROUTING_MODE}
FIREWALL_BACKEND=${FIREWALL_BACKEND}" >/etc/wireguard/params
	chmod 600 /etc/wireguard/params

	# Add server interface
	writeServerConfig "/etc/wireguard/${SERVER_WG_NIC}.conf" "" "" ""

	# Enable routing on the server
	printf '%s\n' "$(buildSysctlConfig "${PUBLIC_ROUTING_MODE}")" >/etc/sysctl.d/wg.conf
	sysctl --system >/dev/null

	systemctl enable --now "wg-quick@${SERVER_WG_NIC}"

	refreshPublicIpv4AnnouncementService

	newClient
	echo -e "${GREEN}If you want to add more clients, you simply need to run this script another time!${NC}"

	# Check if WireGuard is running
	systemctl is-active --quiet "wg-quick@${SERVER_WG_NIC}"
	WG_RUNNING=$?

	# WireGuard might not work if we updated the kernel. Tell the user to reboot
	if [[ ${WG_RUNNING} -ne 0 ]]; then
		echo -e "\n${RED}WARNING: WireGuard does not seem to be running.${NC}"
		echo -e "${ORANGE}You can check if WireGuard is running with: systemctl status wg-quick@${SERVER_WG_NIC}${NC}"
		echo -e "${ORANGE}If you get something like \"Cannot find device ${SERVER_WG_NIC}\", please reboot!${NC}"
	else # WireGuard is running
		echo -e "\n${GREEN}WireGuard is running.${NC}"
		echo -e "${GREEN}You can check the status of WireGuard with: systemctl status wg-quick@${SERVER_WG_NIC}\n\n${NC}"
		echo -e "${ORANGE}If you don't have internet connectivity from your client, try to reboot the server.${NC}"
	fi
}

function newClient() {
	# If SERVER_PUB_IP is IPv6, add brackets if missing
	if [[ ${SERVER_PUB_IP} =~ .*:.* ]]; then
		if [[ ${SERVER_PUB_IP} != *"["* ]] || [[ ${SERVER_PUB_IP} != *"]"* ]]; then
			SERVER_PUB_IP="[${SERVER_PUB_IP}]"
		fi
	fi
	ENDPOINT="${SERVER_PUB_IP}:${SERVER_PORT}"

	echo ""
	echo "Client configuration"
	echo ""
	echo "The client name must consist of alphanumeric character(s). It may also include underscores or dashes and can't exceed 15 chars."

	until [[ ${CLIENT_NAME} =~ ^[a-zA-Z0-9_-]+$ && ${CLIENT_EXISTS} == '0' && ${#CLIENT_NAME} -lt 16 ]]; do
		read -rp "Client name: " -e CLIENT_NAME
		CLIENT_EXISTS=$(grep -c -E "^### Client ${CLIENT_NAME}\$" "/etc/wireguard/${SERVER_WG_NIC}.conf")

		if [[ ${CLIENT_EXISTS} != 0 ]]; then
			echo ""
			echo -e "${ORANGE}A client with the specified name was already created, please choose another name.${NC}"
			echo ""
		fi
	done

	if [[ ${PUBLIC_ROUTING_MODE} == 'yes' ]]; then
		until [[ ${CLIENT_ADDRESS_MODE} =~ ^(private|public|mixed)$ ]]; do
			read -rp "Client address mode [private/public/mixed]: " -e -i private CLIENT_ADDRESS_MODE
		done
	else
		CLIENT_ADDRESS_MODE=private
	fi

	if [[ ${CLIENT_ADDRESS_MODE} != 'public' ]]; then
		for DOT_IP in {2..254}; do
			DOT_EXISTS=$(grep -c "${SERVER_WG_IPV4::-1}${DOT_IP}" "/etc/wireguard/${SERVER_WG_NIC}.conf")
			if [[ ${DOT_EXISTS} == '0' ]]; then
				break
			fi
		done

		if [[ ${DOT_EXISTS} == '1' ]]; then
			echo ""
			echo "The subnet configured supports only 253 clients."
			exit 1
		fi

		BASE_IPV4=$(echo "${SERVER_WG_IPV4}" | awk -F '.' '{ print $1"."$2"."$3 }')
		BASE_IPV6=$(echo "${SERVER_WG_IPV6}" | awk -F '::' '{ print $1 }')
		DEFAULT_PRIVATE_IPV4="${BASE_IPV4}.${DOT_IP}"
		DEFAULT_PRIVATE_IPV6="${BASE_IPV6}::${DOT_IP}"

		while :; do
			read -rp "Private client IPv4 (leave empty if unused): " -e -i "${DEFAULT_PRIVATE_IPV4}" CLIENT_PRIVATE_IPV4
			if [[ -z ${CLIENT_PRIVATE_IPV4} ]]; then
				break
			fi
			IPV4_EXISTS=$(grep -c -F "${CLIENT_PRIVATE_IPV4}/32" "/etc/wireguard/${SERVER_WG_NIC}.conf")
			if [[ ${IPV4_EXISTS} == '0' ]]; then
				break
			fi
			echo ""
			echo -e "${ORANGE}A client with the specified private IPv4 was already created, please choose another IPv4.${NC}"
			echo ""
		done

		while :; do
			read -rp "Private client IPv6 (leave empty if unused): " -e -i "${DEFAULT_PRIVATE_IPV6}" CLIENT_PRIVATE_IPV6
			if [[ -z ${CLIENT_PRIVATE_IPV6} ]]; then
				break
			fi
			IPV6_EXISTS=$(grep -c -F "${CLIENT_PRIVATE_IPV6}/128" "/etc/wireguard/${SERVER_WG_NIC}.conf")
			if [[ ${IPV6_EXISTS} == '0' ]]; then
				break
			fi
			echo ""
			echo -e "${ORANGE}A client with the specified private IPv6 was already created, please choose another IPv6.${NC}"
			echo ""
		done
	else
		CLIENT_PRIVATE_IPV4=""
		CLIENT_PRIVATE_IPV6=""
	fi

	if [[ ${CLIENT_ADDRESS_MODE} != 'private' ]]; then
		while :; do
			read -rp "Public client IPv4 (leave empty if unused): " -e CLIENT_PUBLIC_IPV4
			if [[ -z ${CLIENT_PUBLIC_IPV4} ]]; then
				break
			fi
			PUBLIC_IPV4_EXISTS=$(grep -c -F "${CLIENT_PUBLIC_IPV4}/32" "/etc/wireguard/${SERVER_WG_NIC}.conf")
			if [[ ${PUBLIC_IPV4_EXISTS} == '0' ]]; then
				break
			fi
			echo ""
			echo -e "${ORANGE}A client with the specified public IPv4 was already created, please choose another IPv4.${NC}"
			echo ""
		done

		while :; do
			read -rp "Public client IPv6 (leave empty if unused): " -e CLIENT_PUBLIC_IPV6
			if [[ -z ${CLIENT_PUBLIC_IPV6} ]]; then
				break
			fi
			PUBLIC_IPV6_EXISTS=$(grep -c -F "${CLIENT_PUBLIC_IPV6}/128" "/etc/wireguard/${SERVER_WG_NIC}.conf")
			if [[ ${PUBLIC_IPV6_EXISTS} == '0' ]]; then
				break
			fi
			echo ""
			echo -e "${ORANGE}A client with the specified public IPv6 was already created, please choose another IPv6.${NC}"
			echo ""
		done
	else
		CLIENT_PUBLIC_IPV4=""
		CLIENT_PUBLIC_IPV6=""
	fi

	if ! validateClientAddressMode \
		"${CLIENT_ADDRESS_MODE}" \
		"${CLIENT_PRIVATE_IPV4}" \
		"${CLIENT_PUBLIC_IPV4}" \
		"${CLIENT_PRIVATE_IPV6}" \
		"${CLIENT_PUBLIC_IPV6}"; then
		echo "The selected client address mode does not match the provided addresses."
		exit 1
	fi

	# Generate key pair for the client
	CLIENT_PRIV_KEY=$(wg genkey)
	CLIENT_PUB_KEY=$(echo "${CLIENT_PRIV_KEY}" | wg pubkey)
	CLIENT_PRE_SHARED_KEY=$(wg genpsk)

	HOME_DIR=$(getHomeDirForClient "${CLIENT_NAME}")

	# Create client file and add the server as a peer
	printf '%s\n' "$(buildClientConfig \
		"${CLIENT_ADDRESS_MODE}" \
		"${SERVER_WG_NIC}" \
		"${CLIENT_PRIV_KEY}" \
		"${SERVER_PUB_KEY}" \
		"${CLIENT_PRE_SHARED_KEY}" \
		"${ENDPOINT}" \
		"${ALLOWED_IPS}" \
		"${CLIENT_DNS_1}" \
		"${CLIENT_DNS_2}" \
		"${CLIENT_PRIVATE_IPV4}" \
		"${CLIENT_PUBLIC_IPV4}" \
		"${CLIENT_PRIVATE_IPV6}" \
		"${CLIENT_PUBLIC_IPV6}")" >"${HOME_DIR}/${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf"

	# Add the client as a peer to the server
	NEW_PEER_BLOCK=$(buildServerPeerBlock \
		"${CLIENT_NAME}" \
		"${CLIENT_ADDRESS_MODE}" \
		"${CLIENT_PUB_KEY}" \
		"${CLIENT_PRE_SHARED_KEY}" \
		"${CLIENT_PRIVATE_IPV4}" \
		"${CLIENT_PUBLIC_IPV4}" \
		"${CLIENT_PRIVATE_IPV6}" \
		"${CLIENT_PUBLIC_IPV6}")
	EXISTING_PEER_BLOCKS=$(getPeerBlocksFromConfig "/etc/wireguard/${SERVER_WG_NIC}.conf")

	if [[ -n ${EXISTING_PEER_BLOCKS} ]]; then
		PEER_BLOCKS="${EXISTING_PEER_BLOCKS}

${NEW_PEER_BLOCK}"
	else
		PEER_BLOCKS="${NEW_PEER_BLOCK}"
	fi

	writeServerConfig \
		"/etc/wireguard/${SERVER_WG_NIC}.conf" \
		"${PEER_BLOCKS}" \
		"$(listPublicIpv4FromConfig "/etc/wireguard/${SERVER_WG_NIC}.conf")
${CLIENT_PUBLIC_IPV4}" \
		"$(listPublicIpv6FromConfig "/etc/wireguard/${SERVER_WG_NIC}.conf")
${CLIENT_PUBLIC_IPV6}"
	refreshPublicIpv4AnnouncementService
	applyWireGuardConfig

	# Generate QR code if qrencode is installed
	if command -v qrencode &>/dev/null; then
		echo -e "${GREEN}\nHere is your client config file as a QR Code:\n${NC}"
		qrencode -t ansiutf8 -l L <"${HOME_DIR}/${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf"
		echo ""
	fi

	echo -e "${GREEN}Your client config file is in ${HOME_DIR}/${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf${NC}"
}

function listClients() {
	NUMBER_OF_CLIENTS=$(grep -c -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf")
	if [[ ${NUMBER_OF_CLIENTS} -eq 0 ]]; then
		echo ""
		echo "You have no existing clients!"
		exit 1
	fi

	grep -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf" | cut -d ' ' -f 3 | nl -s ') '
}

function revokeClient() {
	NUMBER_OF_CLIENTS=$(grep -c -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf")
	if [[ ${NUMBER_OF_CLIENTS} == '0' ]]; then
		echo ""
		echo "You have no existing clients!"
		exit 1
	fi

	echo ""
	echo "Select the existing client you want to revoke"
	grep -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf" | cut -d ' ' -f 3 | nl -s ') '
	until [[ ${CLIENT_NUMBER} -ge 1 && ${CLIENT_NUMBER} -le ${NUMBER_OF_CLIENTS} ]]; do
		if [[ ${CLIENT_NUMBER} == '1' ]]; then
			read -rp "Select one client [1]: " CLIENT_NUMBER
		else
			read -rp "Select one client [1-${NUMBER_OF_CLIENTS}]: " CLIENT_NUMBER
		fi
	done

	# match the selected number to a client name
	CLIENT_NAME=$(grep -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf" | cut -d ' ' -f 3 | sed -n "${CLIENT_NUMBER}"p)

	# remove [Peer] block matching $CLIENT_NAME
	sed -i "/^### Client ${CLIENT_NAME}\$/,/^$/d" "/etc/wireguard/${SERVER_WG_NIC}.conf"

	# remove generated client file
	HOME_DIR=$(getHomeDirForClient "${CLIENT_NAME}")
	rm -f "${HOME_DIR}/${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf"

	# restart wireguard to apply changes
	PEER_BLOCKS=$(getPeerBlocksFromConfig "/etc/wireguard/${SERVER_WG_NIC}.conf")
	writeServerConfig \
		"/etc/wireguard/${SERVER_WG_NIC}.conf" \
		"${PEER_BLOCKS}" \
		"$(listPublicIpv4FromConfig "/etc/wireguard/${SERVER_WG_NIC}.conf")" \
		"$(listPublicIpv6FromConfig "/etc/wireguard/${SERVER_WG_NIC}.conf")"
	refreshPublicIpv4AnnouncementService
	applyWireGuardConfig
}

function uninstallWg() {
	echo ""
	echo -e "\n${RED}WARNING: This will uninstall WireGuard and remove all the configuration files!${NC}"
	echo -e "${ORANGE}Please backup the /etc/wireguard directory if you want to keep your configuration files.\n${NC}"
	read -rp "Do you really want to remove WireGuard? [y/n]: " -e REMOVE
	REMOVE=${REMOVE:-n}
	if [[ $REMOVE == 'y' ]]; then
		removePublicIpv4AnnouncementService

		systemctl disable --now "wg-quick@${SERVER_WG_NIC}"

		case "${OS_FAMILY}" in
		debian)
			apt-get -o DPkg::Lock::Timeout=300 remove -y wireguard wireguard-tools qrencode
			;;
		rhel)
			dnf remove -y --noautoremove wireguard-tools qrencode
			if [[ ${OS} != 'fedora' && ${VERSION_ID%%.*} == 8 ]]; then
				dnf remove -y --noautoremove kmod-wireguard
			fi
			;;
		arch)
			local PACKAGE
			for PACKAGE in wireguard-tools qrencode; do
				if pacman -Qi "${PACKAGE}" &>/dev/null; then
					pacman -Rs --noconfirm "${PACKAGE}"
				fi
			done
			;;
		suse)
			zypper --non-interactive remove wireguard-tools qrencode
			;;
		flatcar)
			# Flatcar ships WireGuard in its read-only /usr, nothing to remove
			;;
		esac

		rm -rf /etc/wireguard
		rm -f /etc/sysctl.d/wg.conf

		# Reload sysctl
		sysctl --system >/dev/null

		# Check if WireGuard is running
		systemctl is-active --quiet "wg-quick@${SERVER_WG_NIC}"
		WG_RUNNING=$?

		if [[ ${WG_RUNNING} -eq 0 ]]; then
			echo "WireGuard failed to uninstall properly."
			exit 1
		else
			echo "WireGuard uninstalled successfully."
			exit 0
		fi
	else
		echo ""
		echo "Removal aborted!"
	fi
}

function manageMenu() {
	echo "Welcome to WireGuard-install!"
	echo "The git repository is available at: https://github.com/tbringuier/wireguard-install"
	echo ""
	echo "It looks like WireGuard is already installed."
	echo ""
	echo "What do you want to do?"
	echo "   1) Add a new user"
	echo "   2) List all users"
	echo "   3) Revoke existing user"
	echo "   4) Uninstall WireGuard"
	echo "   5) Exit"
	until [[ ${MENU_OPTION} =~ ^[1-5]$ ]]; do
		read -rp "Select an option [1-5]: " MENU_OPTION
	done
	case "${MENU_OPTION}" in
	1)
		newClient
		;;
	2)
		listClients
		;;
	3)
		revokeClient
		;;
	4)
		uninstallWg
		;;
	5)
		exit 0
		;;
	esac
}

if [[ "${WG_INSTALL_TESTING:-0}" != 1 ]]; then
	# Check for root, virt, OS...
	initialCheck

	# Check if WireGuard is already installed and load params
	if [[ -e /etc/wireguard/params ]]; then
		source /etc/wireguard/params
		manageMenu
	else
		installWireGuard
	fi
fi
