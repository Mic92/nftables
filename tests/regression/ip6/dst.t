*ip6;test-ip6
*inet;test-inet
:input;type filter hook input priority 0

dst nexthdr 22;ok
dst nexthdr != 233;ok
dst nexthdr 33-45;ok;dst nexthdr >= 33 dst nexthdr <= 45
dst nexthdr != 33-45;ok;dst nexthdr < 33 dst nexthdr > 45
dst nexthdr { 33, 55, 67, 88};ok
- dst nexthdr != { 33, 55, 67, 88};ok
dst nexthdr { 33-55};ok
- dst nexthdr != { 33-55};ok
dst nexthdr { udplite, ipcomp, udp, ah, sctp, esp, dccp, tcp, ipv6-icmp};ok;dst nexthdr { 51, 50, 17, 136, 58, 6, 33, 132, 108}
- dst nexthdr != { udplite, ipcomp, udp, ah, sctp, esp, dccp, tcp, ipv6-icmp};ok
dst nexthdr icmp;ok;dst nexthdr 1
dst nexthdr != icmp;ok;dst nexthdr != 1

dst hdrlength 22;ok
dst hdrlength != 233;ok
dst hdrlength 33-45;ok;dst hdrlength >= 33 dst hdrlength <= 45
dst hdrlength != 33-45;ok;dst hdrlength < 33 dst hdrlength > 45
dst hdrlength { 33, 55, 67, 88};ok
- dst hdrlength != { 33, 55, 67, 88};ok
dst hdrlength { 33-55};ok
- dst hdrlength != { 33-55};ok
