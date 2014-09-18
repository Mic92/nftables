*ip6;test-ip6
- *inet;test-inet
:input;type nat hook input priority 0

tcp dport 80-90 dnat 2001:838:35f:1::-2001:838:35f:2:: :80-100;ok
tcp dport 80-90 dnat 2001:838:35f:1::-2001:838:35f:2:: :100;ok
