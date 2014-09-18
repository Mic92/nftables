*ip6;test-ip6
*inet;test-inet
:input;type filter hook input priority 0

rt nexthdr 1;ok
rt nexthdr != 1;ok
rt nexthdr {udplite, ipcomp, udp, ah, sctp, esp, dccp, tcp, ipv6-icmp};ok;rt nexthdr { 33, 136, 50, 132, 51, 17, 108, 6, 58}
- rt nexthdr != {udplite, ipcomp, udp, ah, sctp, esp, dccp, tcp, ipv6-icmp};ok
rt nexthdr icmp;ok;rt nexthdr 1
rt nexthdr != icmp;ok;rt nexthdr != 1
rt nexthdr 22;ok
rt nexthdr != 233;ok
rt nexthdr 33-45;ok;rt nexthdr >= 33 rt nexthdr <= 45
rt nexthdr != 33-45;ok;rt nexthdr < 33 rt nexthdr > 45
rt nexthdr { 33, 55, 67, 88};ok
- rt nexthdr != { 33, 55, 67, 88};ok
rt nexthdr { 33-55};ok;rt nexthdr { 33-55}
- rt nexthdr != { 33-55};ok

rt hdrlength 22;ok
rt hdrlength != 233;ok
rt hdrlength 33-45;ok;rt hdrlength >= 33 rt hdrlength <= 45
rt hdrlength != 33-45;ok;rt hdrlength < 33 rt hdrlength > 45
rt hdrlength { 33, 55, 67, 88};ok
- rt hdrlength != { 33, 55, 67, 88};ok
rt hdrlength { 33-55};ok
- rt hdrlength != { 33-55};ok

rt type 22;ok
rt type != 233;ok
rt type 33-45;ok;rt type >= 33 rt type <= 45
rt type != 33-45;ok;rt type < 33 rt type > 45
rt type { 33, 55, 67, 88};ok
- rt type != { 33, 55, 67, 88};ok
rt type { 33-55};ok
- rt type != { 33-55};ok

rt seg-left 22;ok
rt seg-left != 233;ok
rt seg-left 33-45;ok;rt seg-left >= 33 rt seg-left <= 45
rt seg-left != 33-45;ok;rt seg-left < 33 rt seg-left > 45
rt seg-left { 33, 55, 67, 88};ok
- rt seg-left != { 33, 55, 67, 88};ok
rt seg-left { 33-55};ok
- rt seg-left != { 33-55};ok
