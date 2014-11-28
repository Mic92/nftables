*ip;test-ip4
*ip6;test-ip6
*inet;test-inet
# ct expresion is not supported in arp and bridge family yet.
- *arp;test-arp
- *bridge;test-bridge

:output;type filter hook output priority 0

ct state new,established, related, untracked;ok;ct state established,related,new,untracked
ct state != related;ok
ct state {new,established, related, untracked};ok
- ct state != {new,established, related, untracked};ok
ct state invalid drop;ok
ct state established accept;ok
ct state 8;ok;ct state new

ct direction original;ok
ct direction != original;ok
ct direction reply;ok
ct direction != reply;ok
ct direction {reply, original};ok
- ct direction != {reply, original};ok

ct status expected;ok
ct status != expected;ok
ct status seen-reply;ok
ct status != seen-reply;ok
ct status {expected, seen-reply, assured, confirmed, dying};ok

# SYMBOL("snat", IPS_SRC_NAT)
# SYMBOL("dnat", IPS_DST_NAT)
- ct status snat;ok
- ct status dnat;ok

ct mark 0;ok;ct mark 0x00000000
ct mark or 0x23 == 0x11;ok;ct mark | 0x00000023 == 0x00000011
ct mark or 0x3 != 0x1;ok;ct mark | 0x00000003 != 0x00000001
ct mark and 0x23 == 0x11;ok;ct mark & 0x00000023 == 0x00000011
ct mark and 0x3 != 0x1;ok;ct mark & 0x00000003 != 0x00000001
ct mark xor 0x23 == 0x11;ok;ct mark 0x00000032
ct mark xor 0x3 != 0x1;ok;ct mark != 0x00000002

ct mark 0x32;ok;ct mark 0x00000032
ct mark != 0x32;ok;ct mark != 0x00000032
ct mark 0x32-0x45;ok;ct mark >= 0x00000032 ct mark <= 0x45000000
ct mark != 0x32-0x43;ok;ct mark < 0x00000032 ct mark > 0x43000000
ct mark {0x32, 0x2222, 0x42de3};ok;ct mark { 0x00042de3, 0x00002222, 0x00000032}
- ct mark != {0x32, 0x2222, 0x42de3};ok

# ct mark != {0x32, 0x2222, 0x42de3};ok
# BUG: invalid expression type set
# nft: src/evaluate.c:975: expr_evaluate_relational: Assertion '0' failed.

ct mark set 0x11 xor 0x1331;ok;ct mark set 0x00001320
ct mark set 0x11333 and 0x11;ok;ct mark set 0x00000011
ct mark set 0x12 or 0x11;ok;ct mark set 0x00000013
ct mark set 0x11;ok;ct mark set 0x00000011

ct expiration 30;ok
ct expiration 22;ok
ct expiration != 233;ok
ct expiration 33-45;ok
# BUG: ct expiration 33-45 and  ct expiration != 33-45
# Broken output: ct expiration >= "33s" ct expiration <= "9709d53m20s"
ct expiration != 33-45;ok
ct expiration {33, 55, 67, 88};ok
- ct expiration != {33, 55, 67, 88};ok
ct expiration {33-55};ok
# BUG: ct expiration {33-55}
# Broken output: ct expiration { "4271d23h25m52s"-"8738d3h11m59s" }
- ct expiration != {33-55};ok

ct helper "ftp";ok
ct helper "12345678901234567";fail

# BUG: ct l3proto "Layer  3 protocol of the connection"
# nft add rule ip test input ct l3proto arp
# <cmdline>:1:35-37: Error: Can t parse symbolic invalid expressions


# If table is ip6 or inet or bridge family,, It is failed. I can not test it
# ct saddr 1.2.3.4;ok

# BUG: ct saddr 192.168.3.4
# <cmdline>:1:1-43: Error: Could not process rule: Invalid argument
# add rule ip test input ct saddr 192.168.3.4
# ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
- ct saddr 192.168.3.4;ok
- ct daddr 192.168.3.4;ok

# BUG: ct protocol tcp
# <cmdline>:1:1-37: Error: Could not process rule: Invalid argument
# input ct protocol bgp <cmdline>:1:36-38: Error: Could not resolve protocol name
# ct protocol tcp;ok
- ct protocol tcp;ok

- ct proto-src udp;ok
- ct proto-dst udp;ok
# BUG: ct proto-src udp and ct proto-dst udp
# <cmdline>:1:37-39: Error: datatype mismatch, expected invalid, expression has type Internet protocol
# add rule ip test input ct proto-src udp
#                       ~~~~~~~~~~~~ ^^^
# <cmdline>:1:37-39: Error: datatype mismatch, expected invalid, expression has type Internet protocol
# add rule ip test input ct proto-dst udp
#                        ~~~~~~~~~~~~ ^^^
