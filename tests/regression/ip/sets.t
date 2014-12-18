*ip;test-ip4
*inet;test-inet
:input;type filter hook input priority 0

!set_ipv4_add ipv4_addr;ok
!set_inet inet_proto;ok
!set_inet_serv inet_service;ok
!set_time time;ok

!set1 ipv4_addr;ok
?set1 192.168.3.4;ok

?set1 192.168.3.4;fail
?set1 192.168.3.5 192.168.3.6;ok
?set1 192.168.3.5 192.168.3.6;fail
?set1 192.168.3.8 192.168.3.9;ok
?set1 192.168.3.10 192.168.3.11;ok
?set1 1234:1234:1234:1234:1234:1234:1234:1234;fail
?set2 192.168.3.4;fail

!set2 ipv4_addr;ok
?set2 192.168.3.4;ok
?set2 192.168.3.5 192.168.3.6;ok
?set2 192.168.3.5 192.168.3.6;fail
?set2 192.168.3.8 192.168.3.9;ok
?set2 192.168.3.10 192.168.3.11;ok

ip saddr @set1 drop;ok
ip saddr @set2 drop;ok
ip saddr @set33 drop;fail
