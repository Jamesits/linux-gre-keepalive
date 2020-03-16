#!/bin/bash
set -Eeuo pipefail

# Usage: 
#   try_load tunnel_type xdp_executable tunnel_config
try_load() {
    TUNNEL_TYPE=$1
    XDP_EXECUTABLE=$2
    TUNNEL_CONFIG=${@:3}
    TUNNEL_INTERFACE_NAME=test1

    echo "Testing ${XDP_EXECUTABLE} on ${TUNNEL_TYPE}..."

    ip link del ${TUNNEL_INTERFACE_NAME} || true
    ip link add ${TUNNEL_INTERFACE_NAME} type ${TUNNEL_TYPE} ${TUNNEL_CONFIG}
    ip link set ${TUNNEL_INTERFACE_NAME} up
    ip link set dev ${TUNNEL_INTERFACE_NAME} xdp object "${XDP_EXECUTABLE}"
    ip link del ${TUNNEL_INTERFACE_NAME}
}

if [ $EUID -ne 0 ]; then
    echo "This script must be run as root"
    exit 1
fi

cd "$( dirname "${BASH_SOURCE[0]}" )"/..

modprobe ip_gre

try_load gre build/keepalive_gre.o local 169.254.1.1 remote 169.254.1.2 ttl 255
try_load ip6gre build/keepalive_gre6.o local fd00::1 remote fd00::2 ttl 255
