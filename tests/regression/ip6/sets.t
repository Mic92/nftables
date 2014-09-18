*ip6;test-ip6
*inet;test-inet
:input;type filter hook input priority 0

!set_ipv6_add1 ipv6_addr;ok
!set_inet1 inet_proto;ok
!set_inet inet_service;ok
!set_time time;ok

?set2 192.168.3.4;fail
!set2 ipv6_addr;ok
?set2 1234:1234::1234:1234:1234:1234:1234;ok
?set2 1234:1234::1234:1234:1234:1234:1234;fail
?set2 1234::1234:1234:1234;ok
?set2 1234:1234:1234:1234:1234::1234:1234 1234:1234::123;ok
?set2 192.168.3.8 192.168.3.9;fail
?set2 1234:1234::1234:1234:1234:1234;ok
?set2 1234:1234::1234:1234:1234:1234;fail
?set2 1234:1234:1234::1234;ok

ip6 saddr @set2 drop;ok
ip6 saddr @set33 drop;fail
