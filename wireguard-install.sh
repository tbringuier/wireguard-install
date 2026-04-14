#!/bin/bash

# Secure WireGuard server installer
# https://github.com/angristan/wireguard-install

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
		"${PRIVATE_IPV6:+${PRIVATE_IPV6}/128}"
	do
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
		[[ ( -n ${PRIVATE_IPV4} || -n ${PRIVATE_IPV6} ) && -z ${PUBLIC_IPV4} && -z ${PUBLIC_IPV6} ]]
		;;
	public)
		[[ ( -n ${PUBLIC_IPV4} || -n ${PUBLIC_IPV6} ) && -z ${PRIVATE_IPV4} && -z ${PRIVATE_IPV6} ]]
		;;
	mixed)
		[[ ( -n ${PRIVATE_IPV4} || -n ${PRIVATE_IPV6} ) && ( -n ${PUBLIC_IPV4} || -n ${PUBLIC_IPV6} ) ]]
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
	done <<< "${PUBLIC_IPV4_LIST}"

	while IFS= read -r PUBLIC_IPV6; do
		[[ -n ${PUBLIC_IPV6} ]] || continue
		RULES="${RULES}
PostUp = ip6tables -I FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_WG_NIC} -d ${PUBLIC_IPV6}/128 -j ACCEPT
PostUp = ip6tables -I FORWARD -i ${SERVER_WG_NIC} -s ${PUBLIC_IPV6}/128 -j ACCEPT
PostDown = ip6tables -D FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_WG_NIC} -d ${PUBLIC_IPV6}/128 -j ACCEPT
PostDown = ip6tables -D FORWARD -i ${SERVER_WG_NIC} -s ${PUBLIC_IPV6}/128 -j ACCEPT"
	done <<< "${PUBLIC_IPV6_LIST}"

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

function buildArpingOpenrcService() {
	echo '#!/sbin/openrc-run
description="WireGuard public IPv4 announcement loop"
command="/etc/wireguard/wg-public-ipv4-arping.sh"
command_background="yes"
pidfile="/run/${RC_SVCNAME}.pid"

depend() {
	after net
}'
}

function refreshPublicIpv4AnnouncementService() {
	local WG_CONF_FILE="/etc/wireguard/${SERVER_WG_NIC}.conf"

	if [[ ${PUBLIC_ROUTING_MODE} != 'yes' ]]; then
		return
	fi

	rebuildPublicIpv4Inventory "${WG_CONF_FILE}" "/etc/wireguard/public-ipv4.list"
	printf '%s\n' "$(buildArpingLoopScript)" >/etc/wireguard/wg-public-ipv4-arping.sh
	chmod +x /etc/wireguard/wg-public-ipv4-arping.sh

	if [[ ${OS} == 'alpine' ]]; then
		printf '%s\n' "$(buildArpingOpenrcService)" >/etc/init.d/wg-public-ipv4-arping
		chmod +x /etc/init.d/wg-public-ipv4-arping
		rc-update add wg-public-ipv4-arping >/dev/null 2>&1 || true
		rc-service wg-public-ipv4-arping restart >/dev/null 2>&1 || rc-service wg-public-ipv4-arping start >/dev/null 2>&1
	else
		printf '%s\n' "$(buildArpingSystemdService)" >/etc/systemd/system/wg-public-ipv4-arping.service
		systemctl daemon-reload
		systemctl enable wg-public-ipv4-arping >/dev/null 2>&1
		systemctl restart wg-public-ipv4-arping >/dev/null 2>&1 || systemctl start wg-public-ipv4-arping >/dev/null 2>&1
	fi
}

function removePublicIpv4AnnouncementService() {
	if [[ ${PUBLIC_ROUTING_MODE} != 'yes' ]]; then
		return
	fi

	if [[ ${OS} == 'alpine' ]]; then
		rc-service wg-public-ipv4-arping stop >/dev/null 2>&1 || true
		rc-update del wg-public-ipv4-arping >/dev/null 2>&1 || true
		rm -f /etc/init.d/wg-public-ipv4-arping
	else
		systemctl stop wg-public-ipv4-arping >/dev/null 2>&1 || true
		systemctl disable wg-public-ipv4-arping >/dev/null 2>&1 || true
		rm -f /etc/systemd/system/wg-public-ipv4-arping.service
		systemctl daemon-reload
	fi

	rm -f /etc/wireguard/wg-public-ipv4-arping.sh
	rm -f /etc/wireguard/public-ipv4.list
}

function applyWireGuardConfig() {
	if [[ ${PUBLIC_ROUTING_MODE} == 'yes' ]]; then
		if [[ ${OS} == 'alpine' ]]; then
			rc-service "wg-quick.${SERVER_WG_NIC}" restart
		else
			systemctl restart "wg-quick@${SERVER_WG_NIC}"
		fi
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

function isRoot() {
	if [ "${EUID}" -ne 0 ]; then
		echo "You need to run this script as root"
		exit 1
	fi
}

function checkVirt() {
	if command -v virt-what &>/dev/null; then
		VIRT=$(virt-what)
	else
		VIRT=$(systemd-detect-virt)
	fi
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
	source /etc/os-release
	OS="${ID}"
	if [[ ${OS} == "debian" || ${OS} == "raspbian" ]]; then
		if [[ ${VERSION_ID} -lt 10 ]]; then
			echo "Your version of Debian (${VERSION_ID}) is not supported. Please use Debian 10 Buster or later"
			exit 1
		fi
		OS=debian # overwrite if raspbian
	elif [[ ${OS} == "ubuntu" ]]; then
		RELEASE_YEAR=$(echo "${VERSION_ID}" | cut -d'.' -f1)
		if [[ ${RELEASE_YEAR} -lt 18 ]]; then
			echo "Your version of Ubuntu (${VERSION_ID}) is not supported. Please use Ubuntu 18.04 or later"
			exit 1
		fi
	elif [[ ${OS} == "fedora" ]]; then
		if [[ ${VERSION_ID} -lt 32 ]]; then
			echo "Your version of Fedora (${VERSION_ID}) is not supported. Please use Fedora 32 or later"
			exit 1
		fi
	elif [[ ${OS} == 'centos' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]]; then
		if [[ ${VERSION_ID} == 7* ]]; then
			echo "Your version of CentOS (${VERSION_ID}) is not supported. Please use CentOS 8 or later"
			exit 1
		fi
	elif [[ -e /etc/oracle-release ]]; then
		source /etc/os-release
		OS=oracle
	elif [[ -e /etc/arch-release ]]; then
		OS=arch
	elif [[ -e /etc/alpine-release ]]; then
		OS=alpine
		if ! command -v virt-what &>/dev/null; then
			if ! (apk update && apk add virt-what); then
				echo -e "${RED}Failed to install virt-what. Continuing without virtualization check.${NC}"
			fi
		fi
	elif [[ ${OS} == "flatcar" ]] || [[ ${OS} == "coreos" && -n "${FLATCAR_BOARD:-}" ]]; then
		OS=flatcar
	else
		echo "Looks like you aren't running this installer on a Debian, Ubuntu, Fedora, CentOS, AlmaLinux, Rocky, Oracle, Arch, Alpine or Flatcar Linux system"
		exit 1
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
	checkOS
	checkVirt
}

function installQuestions() {
	echo "Welcome to the WireGuard installer!"
	echo "The git repository is available at: https://github.com/angristan/wireguard-install"
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

	if pgrep firewalld >/dev/null; then
		validatePublicRoutingEnvironment "${PUBLIC_ROUTING_MODE}" "yes" || exit 1
		FIREWALL_BACKEND=$(selectFirewallBackend "${PUBLIC_ROUTING_MODE}" "yes")
	else
		validatePublicRoutingEnvironment "${PUBLIC_ROUTING_MODE}" "no" || exit 1
		FIREWALL_BACKEND=$(selectFirewallBackend "${PUBLIC_ROUTING_MODE}" "no")
	fi

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
	if [[ ${OS} == 'ubuntu' ]] || [[ ${OS} == 'debian' && ${VERSION_ID} -gt 10 ]]; then
		apt-get update
		installPackages apt-get install -y wireguard iptables resolvconf qrencode
		if [[ ${PUBLIC_ROUTING_MODE} == 'yes' ]]; then
			installPackages apt-get install -y iputils-arping
		fi
	elif [[ ${OS} == 'debian' ]]; then
		if ! grep -rqs "^deb .* buster-backports" /etc/apt/; then
			echo "deb http://deb.debian.org/debian buster-backports main" >/etc/apt/sources.list.d/backports.list
			apt-get update
		fi
		apt-get update
		installPackages apt-get install -y iptables resolvconf qrencode
		installPackages apt-get install -y -t buster-backports wireguard
		if [[ ${PUBLIC_ROUTING_MODE} == 'yes' ]]; then
			installPackages apt-get install -y iputils-arping
		fi
	elif [[ ${OS} == 'fedora' ]]; then
		if [[ ${VERSION_ID} -lt 32 ]]; then
			installPackages dnf install -y dnf-plugins-core
			dnf copr enable -y jdoss/wireguard
			installPackages dnf install -y wireguard-dkms
		fi
		installPackages dnf install -y wireguard-tools iptables qrencode
		if [[ ${PUBLIC_ROUTING_MODE} == 'yes' ]]; then
			installPackages dnf install -y iputils
		fi
	elif [[ ${OS} == 'centos' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]]; then
		if [[ ${VERSION_ID} == 8* ]]; then
			installPackages yum install -y epel-release elrepo-release
			installPackages yum install -y kmod-wireguard
			yum install -y qrencode || true # not available on release 9
		fi
		installPackages yum install -y wireguard-tools iptables
		if [[ ${PUBLIC_ROUTING_MODE} == 'yes' ]]; then
			installPackages yum install -y iputils
		fi
	elif [[ ${OS} == 'oracle' ]]; then
		installPackages dnf install -y oraclelinux-developer-release-el8
		dnf config-manager --disable -y ol8_developer
		dnf config-manager --enable -y ol8_developer_UEKR6
		dnf config-manager --save -y --setopt=ol8_developer_UEKR6.includepkgs='wireguard-tools*'
		installPackages dnf install -y wireguard-tools qrencode iptables
		if [[ ${PUBLIC_ROUTING_MODE} == 'yes' ]]; then
			installPackages dnf install -y iputils
		fi
	elif [[ ${OS} == 'arch' ]]; then
		installPackages pacman -S --needed --noconfirm wireguard-tools qrencode
		if [[ ${PUBLIC_ROUTING_MODE} == 'yes' ]]; then
			installPackages pacman -S --needed --noconfirm iputils
		fi
	elif [[ ${OS} == 'flatcar' ]]; then
		# Flatcar provides the required WireGuard tooling natively
		:
	elif [[ ${OS} == 'alpine' ]]; then
		apk update
		installPackages apk add wireguard-tools iptables libqrencode-tools
		if [[ ${PUBLIC_ROUTING_MODE} == 'yes' ]]; then
			installPackages apk add arping
		fi
	fi

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

	# Make sure the directory exists (this does not seem the be the case on fedora)
	mkdir /etc/wireguard >/dev/null 2>&1

	chmod 600 -R /etc/wireguard/

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

	# Add server interface
	writeServerConfig "/etc/wireguard/${SERVER_WG_NIC}.conf" "" "" ""

	# Enable routing on the server
	printf '%s\n' "$(buildSysctlConfig "${PUBLIC_ROUTING_MODE}")" >/etc/sysctl.d/wg.conf

	if [[ ${OS} == 'fedora' ]]; then
		chmod -v 700 /etc/wireguard
		chmod -v 600 /etc/wireguard/*
	fi

	if [[ ${OS} == 'alpine' ]]; then
		sysctl -p /etc/sysctl.d/wg.conf
		rc-update add sysctl
		ln -s /etc/init.d/wg-quick "/etc/init.d/wg-quick.${SERVER_WG_NIC}"
		rc-service "wg-quick.${SERVER_WG_NIC}" start
		rc-update add "wg-quick.${SERVER_WG_NIC}"
	else
		sysctl --system

		systemctl start "wg-quick@${SERVER_WG_NIC}"
		systemctl enable "wg-quick@${SERVER_WG_NIC}"
	fi

	refreshPublicIpv4AnnouncementService

	newClient
	echo -e "${GREEN}If you want to add more clients, you simply need to run this script another time!${NC}"

	# Check if WireGuard is running
	if [[ ${OS} == 'alpine' ]]; then
		rc-service --quiet "wg-quick.${SERVER_WG_NIC}" status
	else
		systemctl is-active --quiet "wg-quick@${SERVER_WG_NIC}"
	fi
	WG_RUNNING=$?

	# WireGuard might not work if we updated the kernel. Tell the user to reboot
	if [[ ${WG_RUNNING} -ne 0 ]]; then
		echo -e "\n${RED}WARNING: WireGuard does not seem to be running.${NC}"
		if [[ ${OS} == 'alpine' ]]; then
			echo -e "${ORANGE}You can check if WireGuard is running with: rc-service wg-quick.${SERVER_WG_NIC} status${NC}"
		else
			echo -e "${ORANGE}You can check if WireGuard is running with: systemctl status wg-quick@${SERVER_WG_NIC}${NC}"
		fi
		echo -e "${ORANGE}If you get something like \"Cannot find device ${SERVER_WG_NIC}\", please reboot!${NC}"
	else # WireGuard is running
		echo -e "\n${GREEN}WireGuard is running.${NC}"
		if [[ ${OS} == 'alpine' ]]; then
			echo -e "${GREEN}You can check the status of WireGuard with: rc-service wg-quick.${SERVER_WG_NIC} status\n\n${NC}"
		else
			echo -e "${GREEN}You can check the status of WireGuard with: systemctl status wg-quick@${SERVER_WG_NIC}\n\n${NC}"
		fi
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
		"${CLIENT_PUBLIC_IPV6}"
	then
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
		checkOS
		removePublicIpv4AnnouncementService

		if [[ ${OS} == 'alpine' ]]; then
			rc-service "wg-quick.${SERVER_WG_NIC}" stop
			rc-update del "wg-quick.${SERVER_WG_NIC}"
			unlink "/etc/init.d/wg-quick.${SERVER_WG_NIC}"
			rc-update del sysctl
		else
			systemctl stop "wg-quick@${SERVER_WG_NIC}"
			systemctl disable "wg-quick@${SERVER_WG_NIC}"
		fi

		if [[ ${OS} == 'ubuntu' ]] || [[ ${OS} == 'debian' ]]; then
			apt-get remove -y wireguard wireguard-tools qrencode
		elif [[ ${OS} == 'fedora' ]]; then
			dnf remove -y --noautoremove wireguard-tools qrencode
			if [[ ${VERSION_ID} -lt 32 ]]; then
				dnf remove -y --noautoremove wireguard-dkms
				dnf copr disable -y jdoss/wireguard
			fi
		elif [[ ${OS} == 'centos' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]]; then
			yum remove -y --noautoremove wireguard-tools
			if [[ ${VERSION_ID} == 8* ]]; then
				yum remove --noautoremove kmod-wireguard qrencode
			fi
		elif [[ ${OS} == 'oracle' ]]; then
			yum remove --noautoremove wireguard-tools qrencode
		elif [[ ${OS} == 'arch' ]]; then
			pacman -Rs --noconfirm wireguard-tools qrencode
		elif [[ ${OS} == 'flatcar' ]]; then
			# Flatcar provides the required WireGuard tooling natively
			:
		elif [[ ${OS} == 'alpine' ]]; then
			(cd qrencode-4.1.1 || exit && make uninstall)
			rm -rf qrencode-* || exit
			apk del wireguard-tools libqrencode libqrencode-tools
		fi

		rm -rf /etc/wireguard
		rm -f /etc/sysctl.d/wg.conf

		if [[ ${OS} == 'alpine' ]]; then
			rc-service --quiet "wg-quick.${SERVER_WG_NIC}" status &>/dev/null
		else
			# Reload sysctl
			sysctl --system

			# Check if WireGuard is running
			systemctl is-active --quiet "wg-quick@${SERVER_WG_NIC}"
		fi
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
	echo "The git repository is available at: https://github.com/angristan/wireguard-install"
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
