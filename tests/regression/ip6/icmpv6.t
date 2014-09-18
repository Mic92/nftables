*ip6;test-ip4
# BUG: There is a bug with icmpv6 and inet tables
- *inet;test-inet
:input;type filter hook input priority 0

icmpv6 type destination-unreachable accept;ok
icmpv6 type packet-too-big accept;ok
icmpv6 type time-exceeded accept;ok
icmpv6 type echo-request accept;ok
icmpv6 type echo-reply accept;ok
icmpv6 type mld-listener-query accept;ok
icmpv6 type mld-listener-report accept;ok
icmpv6 type mld-listener-reduction accept;ok
icmpv6 type nd-router-solicit accept;ok
icmpv6 type nd-router-advert accept;ok
icmpv6 type nd-neighbor-solicit accept;ok
icmpv6 type nd-neighbor-advert accept;ok
icmpv6 type nd-redirect accept;ok
icmpv6 type router-renumbering accept;ok
icmpv6 type {destination-unreachable, time-exceeded, nd-router-solicit} accept;ok
icmpv6 type {router-renumbering, mld-listener-reduction, time-exceeded, nd-router-solicit} accept;ok
icmpv6 type {mld-listener-query, time-exceeded, nd-router-advert} accept;ok
- icmpv6 type != {mld-listener-query, time-exceeded, nd-router-advert} accept;ok

icmpv6 code 4;ok
icmpv6 code 3-66;ok;icmpv6 code >= 3 icmpv6 code <= 66
icmpv6 code {5, 6, 7} accept;ok
- icmpv6 code != {3, 66, 34};ok
icmpv6 code { 3-66};ok
- icmpv6 code != { 3-44};ok

icmpv6 checksum 2222 log;ok
icmpv6 checksum != 2222 log;ok
icmpv6 checksum 222-226;ok;icmpv6 checksum >= 222 icmpv6 checksum <= 226
icmpv6 checksum != 2222 log;ok
icmpv6 checksum { 222, 226};ok
- icmpv6 checksum != { 222, 226};ok
icmpv6 checksum { 222-226};ok
- icmpv6 checksum != { 222-226};ok

# BUG: icmpv6 parameter-problem, pptr, mtu, packet-too-big
# [ICMP6HDR_PPTR]         = ICMP6HDR_FIELD("parameter-problem", icmp6_pptr),
# [ICMP6HDR_MTU]          = ICMP6HDR_FIELD("packet-too-big", icmp6_mtu),
# $ sudo nft add rule ip6 test6 input icmpv6 parameter-problem 35
# <cmdline>:1:53-53: Error: syntax error, unexpected end of file
# add rule ip6 test6 input icmpv6 parameter-problem 35
#                                                    ^
# $ sudo nft add rule ip6 test6 input icmpv6 parameter-problem
# <cmdline>:1:26-31: Error: Value 58 exceeds valid range 0-0
# add rule ip6 test6 input icmpv6 parameter-problem
#                         ^^^^^^
# $ sudo nft add rule ip6 test6 input icmpv6 parameter-problem 2-4
# <cmdline>:1:54-54: Error: syntax error, unexpected end of file
# add rule ip6 test6 input icmpv6 parameter-problem 2-4

# BUG: packet-too-big
# $ sudo nft add rule ip6 test6 input icmpv6 packet-too-big 34
# <cmdline>:1:50-50: Error: syntax error, unexpected end of file
# add rule ip6 test6 input icmpv6 packet-too-big 34

icmpv6 mtu 22;ok
icmpv6 mtu != 233;ok
icmpv6 mtu 33-45;ok
icmpv6 mtu != 33-45;ok
icmpv6 mtu {33, 55, 67, 88};ok
- icmpv6 mtu != {33, 55, 67, 88};ok
icmpv6 mtu {33-55};ok
- icmpv6 mtu != {33-55};ok

- icmpv6 id 2;ok
- icmpv6 id != 233;ok
icmpv6 id 33-45;ok
icmpv6 id != 33-45;ok
icmpv6 id {33, 55, 67, 88};ok
- icmpv6 id != {33, 55, 67, 88};ok
icmpv6 id {33-55};ok
- icmpv6 id != {33-55};ok

icmpv6 sequence 2;ok
icmpv6 sequence {3, 4, 5, 6, 7} accept;ok

icmpv6 sequence {2, 4};ok
- icmpv6 sequence != {2, 4};ok
icmpv6 sequence 2-4;ok;icmpv6 sequence >= 2 icmpv6 sequence <= 4
icmpv6 sequence != 2-4;ok;icmpv6 sequence < 2 icmpv6 sequence > 4
icmpv6 sequence { 2-4};ok
- icmpv6 sequence != {2-4};ok

- icmpv6 max-delay 22;ok
- icmpv6 max-delay != 233;ok
icmpv6 max-delay 33-45;ok
icmpv6 max-delay != 33-45;ok
icmpv6 max-delay {33, 55, 67, 88};ok
- icmpv6 max-delay != {33, 55, 67, 88};ok
icmpv6 max-delay {33-55};ok
- icmpv6 max-delay != {33-55};ok
