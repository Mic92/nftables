*ip;test-ip4
*inet;test-inet
:input;type filter hook input priority 0

- ip version 2;ok

# bug ip hdrlength
- ip hdrlength 10;ok
- ip hdrlength != 5;ok
- ip hdrlength 5-8;ok
- ip hdrlength != 3-13;ok
- ip hdrlength {3, 5, 6, 8};ok
- ip hdrlength != {3, 5, 7, 8};ok
- ip hdrlength { 3-5};ok
- ip hdrlength != { 3-59};ok
# ip hdrlength 12
# <cmdline>:1:1-38: Error: Could not process rule: Invalid argument
# add rule ip test input ip hdrlength 12
# ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
# <cmdline>:1:37-38: Error: Value 22 exceeds valid range 0-15
# add rule ip test input ip hdrlength 22

- ip dscp CS1;ok
- ip dscp != CS1;ok
- ip dscp 0x38;ok
- ip dscp != 0x20;ok
- ip dscp {CS1, CS2, CS3, CS4, CS5, CS6, CS7, BE, AF11, AF12, AF13, AF21, AF22, AF23, AF31, AF32, AF33, AF41, AF42, AF43, EF};ok
- ip dscp {0x08, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38, 0x00, 0x0a, 0x0c, 0x0e, 0x12, 0x14, 0x16, 0x1a, 0x1c, 0x1e, 0x22, 0x24, 0x26, 0x2e};ok
- ip dscp != {CS0, CS3};ok

ip length 232;ok
ip length != 233;ok
ip length 333-435;ok;ip length >= 333 ip length <= 435
ip length != 333-453;ok;ip length < 333 ip length > 453
ip length { 333, 553, 673, 838};ok
- ip length != { 333, 535, 637, 883};ok
ip length { 333-535};ok
- ip length != { 333-553};ok

ip id 22;ok
ip id != 233;ok
ip id 33-45;ok;ip id >= 33 ip id <= 45
ip id != 33-45;ok;ip id < 33 ip id > 45
ip id { 33, 55, 67, 88};ok
- ip id != { 33, 55, 67, 88};ok
ip id { 33-55};ok
- ip id != { 33-55};ok

ip frag-off 222 accept;ok
ip frag-off != 233;ok
ip frag-off 33-45;ok;ip frag-off >= 33 ip frag-off <= 45
ip frag-off != 33-45;ok;ip frag-off < 33 ip frag-off > 45
ip frag-off { 33, 55, 67, 88};ok
- ip frag-off != { 33, 55, 67, 88};ok
ip frag-off { 33-55};ok
- ip frag-off != { 33-55};ok

ip ttl 0 drop;ok
ip ttl 233 log;ok
ip ttl 33-55;ok;ip ttl >= 33 ip ttl <= 55
ip ttl != 45-50;ok;ip ttl < 45 ip ttl > 50
ip ttl {43, 53, 45 };ok
- ip ttl != {46, 56, 93 };ok
# BUG: ip ttl != {46, 56, 93 };ok
# BUG: invalid expression type set
# nft: src/evaluate.c:975: expr_evaluate_relational: Assertion '0' failed.
ip ttl { 33-55};ok
- ip ttl != { 33-55};ok

ip protocol tcp log;ok;ip protocol 6 log
ip protocol != tcp log;ok;ip protocol != 6 log
ip protocol { icmp, esp, ah, comp, udp, udplite, tcp, dccp, sctp} accept;ok;ip protocol { 33, 136, 17, 51, 50, 6, 132, 1, 108} accept
- ip protocol != { icmp, esp, ah, comp, udp, udplite, tcp, dccp, sctp} accept;ok

ip checksum 13172 drop;ok
ip checksum 22;ok
ip checksum != 233;ok
ip checksum 33-45;ok;ip checksum >= 33 ip checksum <= 45
ip checksum != 33-45;ok;ip checksum < 33 ip checksum > 45
ip checksum { 33, 55, 67, 88};ok
- ip checksum != { 33, 55, 67, 88};ok
ip checksum { 33-55};ok
- ip checksum != { 33-55};ok

ip saddr 192.168.2.0/24;ok
ip saddr != 192.168.2.0/24;ok
ip saddr 192.168.3.1 ip daddr 192.168.3.100;ok
ip saddr != 1.1.1.1 log prefix giuseppe;ok;ip saddr != 1.1.1.1 log prefix "giuseppe"
ip saddr 1.1.1.1 log prefix example group 1;ok;ip saddr 1.1.1.1 log prefix "example" group 1
ip daddr 192.168.0.1-192.168.0.250;ok;ip daddr >= 192.168.0.1 ip daddr <= 192.168.0.250
ip daddr 10.0.0.0-10.255.255.255;ok;ip daddr >= 10.0.0.0 ip daddr <= 10.255.255.255
ip daddr 172.16.0.0-172.31.255.255;ok;ip daddr >= 172.16.0.0 ip daddr <= 172.31.255.255
ip daddr 192.168.3.1-192.168.4.250;ok;ip daddr >= 192.168.3.1 ip daddr <= 192.168.4.250
ip daddr != 192.168.0.1-192.168.0.250;ok;ip daddr < 192.168.0.1 ip daddr > 192.168.0.250
ip daddr { 192.168.0.1-192.168.0.250};ok
- ip daddr != { 192.168.0.1-192.168.0.250};ok
ip daddr { 192.168.5.1, 192.168.5.2, 192.168.5.3 } accept;ok
- ip daddr != { 192.168.5.1, 192.168.5.2, 192.168.5.3 } accept;ok

ip daddr 192.168.1.2-192.168.1.55;ok;ip daddr >= 192.168.1.2 ip daddr <= 192.168.1.55
ip daddr != 192.168.1.2-192.168.1.55;ok;ip daddr < 192.168.1.2 ip daddr > 192.168.1.55
ip saddr 192.168.1.3-192.168.33.55;ok;ip saddr >= 192.168.1.3 ip saddr <= 192.168.33.55
ip saddr != 192.168.1.3-192.168.33.55;ok;ip saddr < 192.168.1.3 ip saddr > 192.168.33.55

ip daddr 192.168.0.1;ok
ip daddr 192.168.0.1 drop;ok
ip daddr 192.168.0.2 log;ok
