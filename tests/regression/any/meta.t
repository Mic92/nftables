*ip;test-ip4
*ip6;test-ip6
*inet;test-inet
*arp;test-arp
*bridge;test-bridge

:input;type filter hook input priority 0

meta length 1000;ok
meta length 22;ok
meta length != 233;ok
meta length 33-45;ok
meta length != 33-45;ok
meta length { 33, 55, 67, 88};ok
- meta length != { 33, 55, 67, 88};ok
meta length { 33-55};ok
- meta length != { 33-55};ok

meta protocol { ip, arp, ip6, vlan };ok;meta protocol { ip6, ip, vlan, arp}
- meta protocol != {ip, arp, ip6, vlan};ok
meta protocol ip;ok
meta protocol != ip;ok

meta nfproto ipv4;ok
meta nfproto ipv6;ok
meta nfproto {ipv4, ipv6};ok

meta l4proto 22;ok
meta l4proto != 233;ok
meta l4proto 33-45;ok;meta l4proto >= 33 meta l4proto <= 45
meta l4proto != 33-45;ok;meta l4proto < 33 meta l4proto > 45
meta l4proto { 33, 55, 67, 88};ok;meta l4proto { 33, 55, 67, 88}
- meta l4proto != { 33, 55, 67, 88};ok
meta l4proto { 33-55};ok
- meta l4proto != { 33-55};ok

- meta priority :aabb;ok
- meta priority bcad:dadc;ok
- meta priority aabb:;ok
- meta priority != :aabb;ok
- meta priority != bcad:dadc;ok
- meta priority != aabb:;ok
- meta priority bcad:dada-bcad:dadc;ok
- meta priority != bcad:dada-bcad:dadc;ok
- meta priority {bcad:dada, bcad:dadc, aaaa:bbbb};ok
- meta priority != {bcad:dada, bcad:dadc, aaaa:bbbb};ok

meta mark 0x4;ok;mark 0x00000004
meta mark 0x32;ok;mark 0x00000032
meta mark and 0x03 == 0x01;ok;mark & 0x00000003 == 0x00000001
meta mark and 0x03 != 0x01;ok;mark & 0x00000003 != 0x00000001
meta mark 0x10;ok;mark 0x00000010
meta mark != 0x10;ok;mark != 0x00000010

meta mark or 0x03 == 0x01;ok;mark | 0x00000003 == 0x00000001
meta mark or 0x03 != 0x01;ok;mark | 0x00000003 != 0x00000001
meta mark xor 0x03 == 0x01;ok;mark 0x00000002
meta mark xor 0x03 != 0x01;ok;mark != 0x00000002

meta iif eth0 accept;ok;iif eth0 accept
meta iif eth0 accept;ok;iif eth0 accept
meta iif != eth0 accept;ok;iif != eth0 accept
meta iif != eth0 accept;ok;iif != eth0 accept

meta iifname "eth0";ok;iifname "eth0"
meta iifname != "eth0";ok;iifname != "eth0"
meta iifname {"eth0", "lo"};ok
- meta iifname != {"eth0", "lo"};ok

meta iiftype {ether, ppp, ipip, ipip6, loopback, sit, ipgre};ok
- meta iiftype != {ether, ppp, ipip, ipip6, loopback, sit, ipgre};ok
meta iiftype != ether;ok;iiftype != ether
meta iiftype ether;ok;iiftype ether
meta iiftype != ppp;ok;iiftype != ppp
meta iiftype ppp;ok;iiftype ppp

meta oif lo accept;ok;oif lo accept
meta oif != lo accept;ok;oif != lo accept
meta oif {eth0, lo} accept;ok
- meta oif != {eth0, lo} accept;ok

meta oifname "eth0";ok;oifname "eth0"
meta oifname != "eth0";ok;oifname != "eth0"
meta oifname { "eth0", "lo"};ok
- meta iifname != {"eth0", "lo"};ok

meta oiftype {ether, ppp, ipip, ipip6, loopback, sit, ipgre};ok
- meta oiftype != {ether, ppp, ipip, ipip6, loopback, sit, ipgre};ok
meta oiftype != ether;ok;oiftype != ether
meta oiftype ether;ok;oiftype ether

meta skuid {man, root, backup} accept;ok;skuid { 0, 6, 34} accept
- meta skuid != {man, root, backup} accept;ok
meta skuid man;ok;skuid 6
meta skuid != man;ok;skuid != 6
meta skuid lt 3000 accept;ok;skuid < 3000 accept
meta skuid gt 3000 accept;ok;skuid > 3000 accept
meta skuid eq 3000 accept;ok;skuid 3000 accept
meta skuid 3001-3005 accept;ok
meta skuid != 2001-2005 accept;ok
meta skuid { 2001-2005} accept;ok
- meta skuid != { 2001-2005} accept;ok

meta skgid {man, root, backup} accept;ok;skgid { 34, 12, 0} accept
- meta skgid != {man, root, backup} accept;ok
meta skgid man;ok;skgid 12
meta skgid != man;ok;skgid != 12
meta skgid lt 3000 accept;ok;skgid < 3000 accept
meta skgid gt 3000 accept;ok;skgid > 3000 accept
meta skgid eq 3000 accept;ok;skgid 3000 accept
meta skgid 2001-2005 accept;ok
meta skgid != 2001-2005 accept;ok
meta skgid { 2001-2005} accept;ok
- meta skgid != { 2001-2005} accept;ok

# BUG: meta nftrace 2 and meta nftrace 1
# $ sudo nft add rule ip test input meta nftrace 2
# <cmdline>:1:37-37: Error: Value 2 exceeds valid range 0-1
# add rule ip test input meta nftrace 2
#                                    ^
# $ sudo nft add rule ip test input meta nftrace 1
# <cmdline>:1:1-37: Error: Could not process rule: Operation not supported
# add rule ip test input meta nftrace 1
# -^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

meta mark set 0xffffffc8 xor 0x16;ok;meta mark set 0xffffffde
meta mark set 0x16 and 0x16;ok;meta mark set 0x00000016
meta mark set 0xffffffe9 or 0x16;ok;meta mark set 0xffffffff
meta mark set 0xffffffde and 0x16;ok;meta mark set 0x00000016
meta mark set 0xf045ffde or 0x10;ok;meta mark set 0xf045ffde
meta mark set 0xffffffde or 0x16;ok;meta mark set 0xffffffde
meta mark set 0x32 or 0xfffff;ok;meta mark set 0x000fffff
meta mark set 0xfffe xor 0x16;ok;meta mark set 0x0000ffe8

meta iif lo;ok;iif lo
meta oif lo;ok;oif lo
meta oifname "eth2" accept;ok;oifname "eth2" accept
meta skuid 3000;ok;skuid 3000
meta skgid 3000;ok;skgid 3000
# BUG:  meta nftrace 1;ok
# <cmdline>:1:1-37: Error: Could not process rule: Operation not supported
- meta nftrace 1;ok
meta rtclassid cosmos;ok;rtclassid cosmos

meta pkttype broadcast;ok;pkttype broadcast
meta pkttype unicast;ok;pkttype unicast
meta pkttype multicast;ok;pkttype multicast
meta pkttype != broadcast;ok;pkttype != broadcast
meta pkttype != unicast;ok;pkttype != unicast
meta pkttype != multicast;ok;pkttype != multicast
meta pkttype broadcastttt;fail
-meta pkttype { broadcast, multicast} accept;ok

meta cpu 1;ok;cpu 1
meta cpu != 1;ok;cpu != 1
meta cpu 1-3;ok;cpu >= 1 cpu <= 3
# BUG: there is not matching of packets with this rule.
meta cpu != 1-2;ok;cpu < 1 cpu > 2
meta cpu { 2,3};ok;cpu { 2, 3}
-meta cpu != { 2,3};ok

meta iifgroup 0;ok;iifgroup default
meta iifgroup != 0;ok;iifgroup != default
meta iifgroup default;ok;iifgroup default
meta iifgroup != default;ok;iifgroup != default
meta iifgroup {default};ok;;iifgroup {default}
- meta iifgroup != {default};ok
meta iifgroup { 11,33};ok
meta iifgroup {11-33};ok
- meta iifgroup != {11,33};ok
- meta iifgroup != {11-33};ok
meta oifgroup 0;ok;oifgroup default
meta oifgroup != 0;ok;oifgroup != default
meta oifgroup default;ok;oifgroup default
meta oifgroup != default;ok;oifgroup != default
meta oifgroup {default};ok;oifgroup {default}
- meta oifgroup != {default};ok
meta oifgroup { 11,33};ok
meta oifgroup {11-33};ok
- meta oifgroup != {11,33};ok
- meta oifgroup != {11-33};ok

meta cgroup 0x100001;ok;cgroup 1048577
meta cgroup != 0x100001;ok;cgroup != 1048577
meta cgroup { 0x100001, 0x100002};ok
# meta cgroup != { 0x100001, 0x100002};ok
meta cgroup 0x100001 - 0x100003;ok
# meta cgroup != 0x100001 - 0x100003;ok
meta cgroup {0x100001 - 0x100003};ok
# meta cgroup != { 0x100001 - 0x100003};ok
