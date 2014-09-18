*ip;test-ip4
*ip6;test-ip6
*inet;test-inet
*arp;test-arp
*bridge;test-bridge
:output;type filter hook output priority 0

frag nexthdr tcp;ok;frag nexthdr 6
frag nexthdr != icmp;ok;frag nexthdr != 1
frag nexthdr {esp, ah, comp, udp, udplite, tcp, dccp, sctp};ok;frag nexthdr { 51, 136, 132, 6, 108, 50, 17, 33}
- frag nexthdr != {esp, ah, comp, udp, udplite, tcp, dccp, sctp};ok
frag nexthdr esp;ok;frag nexthdr 50
frag nexthdr ah;ok;frag nexthdr 51

frag reserved 22;ok
frag reserved != 233;ok
frag reserved 33-45;ok;frag reserved >= 33 frag reserved <= 45
frag reserved != 33-45;ok;frag reserved < 33 frag reserved > 45
frag reserved { 33, 55, 67, 88};ok;frag reserved { 88, 33, 67, 55}
- frag reserved != { 33, 55, 67, 88};ok
frag reserved { 33-55};ok
- frag reserved != { 33-55};ok

# BUG: frag frag-off 22 and frag frag-off { 33-55}
# This breaks table listing: "netlink: Error: Relational expression size mismatch"

- frag frag-off 22;ok
- frag frag-off != 233;ok
- frag frag-off 33-45;ok
- frag frag-off != 33-45;ok
- frag frag-off { 33, 55, 67, 88};ok
- frag frag-off != { 33, 55, 67, 88};ok
- frag frag-off { 33-55};ok
- frag frag-off != { 33-55};ok

# BUG  frag reserved2 33 and frag reserved2 1
# $ sudo nft add rule ip test input frag reserved2 33
# <cmdline>:1:39-40: Error: Value 33 exceeds valid range 0-3
# add rule ip test input frag reserved2 33
#                                      ^^
# sudo nft add rule ip test input frag reserved2 1
# <cmdline>:1:1-39: Error: Could not process rule: Invalid argument
# add rule ip test input frag reserved2 1
# ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

# BUG more-fragments 1 and frag more-fragments 4
# frag more-fragments 1
# <cmdline>:1:1-44: Error: Could not process rule: Invalid argument
# add rule ip test input frag more-fragments 1
# ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
# $ sudo nft add rule ip test input frag more-fragments 4
# <cmdline>:1:44-44: Error: Value 4 exceeds valid range 0-1
# add rule ip test input frag more-fragments 4
#                                           ^

frag id 1;ok
frag id 22;ok
frag id != 33;ok
frag id 33-45;ok;frag id >= 33 frag id <= 45
frag id != 33-45;ok;frag id < 33 frag id > 45
frag id { 33, 55, 67, 88};ok
- frag id != { 33, 55, 67, 88};ok
frag id { 33-55};ok
- frag id != { 33-55};ok
