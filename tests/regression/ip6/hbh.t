*ip6;test-ip6
*inet;test-inet
:filter-input;type filter hook input priority 0

hbh hdrlength 22;ok
hbh hdrlength != 233;ok
hbh hdrlength 33-45;ok;hbh hdrlength >= 33 hbh hdrlength <= 45
hbh hdrlength != 33-45;ok;hbh hdrlength < 33 hbh hdrlength > 45
hbh hdrlength {33, 55, 67, 88};ok
- hbh hdrlength != {33, 55, 67, 88};ok
hbh hdrlength { 33-55};ok
- hbh hdrlength != {33-55};ok

hbh nexthdr {esp, ah, comp, udp, udplite, tcp, dccp, sctp, icmpv6};ok;hbh nexthdr { 58, 136, 51, 50, 6, 17, 132, 33, 108}
- hbh nexthdr != {esp, ah, comp, udp, udplite, tcp, dccp, sctp, icmpv6};ok
hbh nexthdr 22;ok
hbh nexthdr != 233;ok
hbh nexthdr 33-45;ok;hbh nexthdr >= 33 hbh nexthdr <= 45
hbh nexthdr != 33-45;ok;hbh nexthdr < 33 hbh nexthdr > 45
hbh nexthdr {33, 55, 67, 88};ok
- hbh nexthdr != {33, 55, 67, 88};ok
hbh nexthdr { 33-55};ok
- hbh nexthdr != {33-55};ok
hbh nexthdr ip;ok;hbh nexthdr 0
hbh nexthdr != ip;ok;hbh nexthdr != 0
