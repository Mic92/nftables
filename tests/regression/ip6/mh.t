*ip6;test-ip6
*inet;test-inet
:input;type filter hook input priority 0

mh nexthdr 1;ok
mh nexthdr != 1;ok
mh nexthdr { udplite, ipcomp, udp, ah, sctp, esp, dccp, tcp, ipv6-icmp };ok;mh nexthdr { 58, 17, 108, 6, 51, 136, 50, 132, 33}
- mh nexthdr != {udplite, ipcomp, udp, ah, sctp, esp, dccp, tcp, ipv6-icmp};ok
mh nexthdr icmp;ok;mh nexthdr 1
mh nexthdr != icmp;ok;mh nexthdr != 1
mh nexthdr 22;ok
mh nexthdr != 233;ok
mh nexthdr 33-45;ok;mh nexthdr >= 33 mh nexthdr <= 45
mh nexthdr != 33-45;ok;mh nexthdr < 33 mh nexthdr > 45
mh nexthdr { 33, 55, 67, 88 };ok
- mh nexthdr != { 33, 55, 67, 88 };ok
mh nexthdr { 33-55 };ok
- mh nexthdr != { 33-55 };ok

mh hdrlength 22;ok
mh hdrlength != 233;ok
mh hdrlength 33-45;ok;mh hdrlength >= 33 mh hdrlength <= 45
mh hdrlength != 33-45;ok;mh hdrlength < 33 mh hdrlength > 45
mh hdrlength { 33, 55, 67, 88 };ok;mh hdrlength { 67, 33, 88, 55}
- mh hdrlength != { 33, 55, 67, 88 };ok
mh hdrlength { 33-55 };ok
- mh hdrlength != { 33-55 };ok

mh type {binding-refresh-request, home-test-init, careof-test-init, home-test, careof-test, binding-update, binding-acknowledgement, binding-error, fast-binding-update, fast-binding-acknowledgement, fast-binding-advertisement, experimental-mobility-header, home-agent-switch-message};ok
mh type home-agent-switch-message;ok
mh type != home-agent-switch-message;ok

mh reserved 22;ok
mh reserved != 233;ok
mh reserved 33-45;ok;mh reserved >= 33 mh reserved <= 45
mh reserved != 33-45;ok;mh reserved < 33 mh reserved > 45
mh reserved { 33, 55, 67, 88};ok
- mh reserved != {33, 55, 67, 88};ok
mh reserved { 33-55};ok
- mh reserved != { 33-55};ok

mh checksum 22;ok
mh checksum != 233;ok
mh checksum 33-45;ok;mh checksum >= 33 mh checksum <= 45
mh checksum != 33-45;ok;mh checksum < 33 mh checksum > 45
mh checksum { 33, 55, 67, 88};ok
- mh checksum != { 33, 55, 67, 88};ok
mh checksum { 33-55};ok
- mh checksum != { 33-55};ok
