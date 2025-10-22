#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025 Olivier Gournet

. $(dirname $0)/_gtpg_cmd.sh


setup() {
    setup_netns "sgw" "pgw" "cloud"
    sleep 0.5

    # sgw side
    ip link add dev sgw netns sgw address d2:ad:ca:fe:b4:02 type veth \
       peer name sgw address d2:f0:0c:ba:a5:06
    ip -n sgw link set dev sgw up
    ip -n sgw link set dev lo up
    ip -n sgw addr add 192.168.61.5/30 dev sgw
    ip link set dev sgw up
    ip addr add 192.168.61.6/30 dev sgw

    # pgw side
    ip link add dev pgw netns pgw address d2:ad:ca:fe:b4:01 type veth \
       peer name pgw address d2:f0:0c:ba:a5:02
    ip -n pgw link set dev pgw up
    ip -n pgw link set dev lo up
    ip -n pgw addr add 192.168.61.1/30 dev pgw
    ip -n pgw route add default via 192.168.61.2 dev pgw
    ip link set dev pgw up
    ip addr add 192.168.61.2/30 dev pgw

    # ptun side
    ip link add dev veth0 netns cloud address d2:ad:ca:fe:b4:03 type veth \
       peer name gtpptun address d2:f0:0c:ba:05:02
    ip -n cloud link set dev lo up
    ip -n cloud link set dev veth0 up
    ip -n cloud addr add 192.168.61.9/30 dev veth0
    ip -n cloud tunnel add ptun mode ipip local 192.168.61.9 remote 192.168.61.10
    ip -n cloud link set ptun up
    ip -n cloud addr add 192.168.62.1/30 dev ptun
    ip netns exec cloud sysctl -q net.ipv4.conf.veth0.forwarding=1

    ip link set dev gtpptun up
    ip addr add 192.168.61.10/30 dev gtpptun
    ip tunnel add ptun mode ipip local 192.168.61.10 remote 192.168.61.9 dev gtpptun
    ip link set ptun up
    ip addr add 192.168.62.2/30 dev ptun
    sysctl -q net.ipv4.conf.gtpptun.forwarding=1

    # bpf_fib_lookup doesn't start arp'ing if there is no neigh entry,
    # so add static entries
    arp -s 192.168.61.1 d2:ad:ca:fe:b4:01
    arp -s 192.168.61.5 d2:ad:ca:fe:b4:02
    arp -s 192.168.61.9 d2:ad:ca:fe:b4:03

    # fix weird thing with packet checksum sent from a
    # classic socket (eg SOCK_DGRAM).
    ip netns exec cloud ethtool -K veth0 tx-checksumming off >/dev/null

    # remove vlan offload on veth
    ip netns exec cloud ethtool -K veth0 tx-vlan-offload off
    ip netns exec cloud ethtool -K veth0 rx-vlan-offload off
    ethtool -K gtpptun tx-vlan-offload off
    ethtool -K gtpptun rx-vlan-offload off

    # xdp prg must be loaded on the 2 side of veth pair.
    # enabling gro does it too
    ip netns exec cloud ethtool -K veth0 gro on
}

run() {
    # start gtp-guard if not yet started
    start_gtpguard

    gtpg_conf "
bpf-program fwd-1
 path bin/gtp_fwd.bpf
 no shutdown

interface sgw
 bpf-program fwd-1
 no shutdown

interface pgw
 bpf-program fwd-1
 no shutdown

interface gtpptun
 bpf-program fwd-1
 no shutdown

interface ptun
 no shutdown

gtp-proxy gtpp-undertest
 gtpc-tunnel-endpoint 192.168.61.6 port 2123
 gtpc-egress-tunnel-endpoint 192.168.61.2 port 2123
 gtpu-tunnel-endpoint ingress iface sgw port 2152
 gtpu-tunnel-endpoint egress iface pgw
 gtpu-tunnel-endpoint ipip iface ptun
 gtpu-ipip transparent-egress-encap

" || fail "cannot execute vty commands"

    # key: vteid(4) data: vteid(4/be) teid(4) remote_ipv4(4) local_ipv4(4) pkt_stats(remaining) flag(near the end)
    bpftool map update name teid_xlat key hex 00 00 03 01 value hex 01 01 00 00 00 00 00 01 c0 a8 3d 01 c0 a8 3d 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 02 00 00 00 00 00 00 00
    bpftool map update name teid_xlat key hex 00 00 04 01 value hex 01 02 00 00 00 00 00 02 c0 a8 3d 05 c0 a8 3d 06 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00

    gtpg_show "
show interface
show bpf forwarding
show interface-rules
"
}

pkt() {

    (
ip netns exec cloud python3 - <<EOF
from scapy.all import *
def receive(p):
  if IP in p and p[IP].proto == 4:  # IPIP
    # switch eth mac, ipip address, and send back
    tmp = p[IP].src
    p[IP].src = p[IP].dst
    p[IP].dst = tmp
    tmp = p[Ether].src
    p[Ether].src = p[Ether].dst
    p[Ether].dst = tmp
    sendp(p)
p = sniff(count=1, filter=f"ip proto 4", prn=receive)
EOF
    ) &
    python_pid=$!
    sleep 1
    echo "python started: $python_pid"

    send_py_pkt sgw sgw '
p = [Ether(dst="d2:f0:0c:ba:a5:06", src="d2:ad:ca:fe:b4:02") /
  IP(src="192.168.61.5", dst="192.168.61.6") /
  UDP(sport=2152, dport=2152) /
  GTP_U_Header(teid=0x0301, gtp_type=255) /
  Raw("DATADATA")]
'
    wait $python_pid
    cat >> $tmp/cleanup.sh <<EOF
echo "KILLING TUN PYTHON CLIENT"
kill $python_pid
EOF

}

action=${1:-setup}

case $action in
    setup)
	clean
	sleep 2
	setup ;;
    clean)
	clean_netns "sgw" "pgw" "cloud"
	ip tunnel del ptun 2>/dev/null && true
	ip link del gtpptun 2>/dev/null && true
	ip link del ptun 2>/dev/null && true ;;
    run)
	setup
	run ;;
    pkt)
	pkt ;;

    *) fail "action '$action' not recognized" ;;
esac
