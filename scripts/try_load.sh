#!/bin/bash
set -Eeuo pipefail

# Usage: 
#   try_load.sh tunnel_type xdp_executable

TUNNEL_TYPE=$1
XDP_EXECUTABLE=$2
TUNNEL_INTERFACE_NAME=test1

ip link del ${TUNNEL_INTERFACE_NAME}
ip tunnel add ${TUNNEL_INTERFACE_NAME} mode ${TUNNEL_TYPE} local 169.254.1.1 remote 169.254.1.2
ip link set ${TUNNEL_INTERFACE_NAME} up
ip link set dev ${TUNNEL_INTERFACE_NAME} xdp object "${XDP_EXECUTABLE}"
ip link del ${TUNNEL_INTERFACE_NAME}
