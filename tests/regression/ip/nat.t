*ip;test-ip4
# bug: Nat tables is not supported yet in inet table.
-*inet;test-inet

:output;type nat hook output priority 0

iifname eth0 tcp dport 80-90 dnat 192.168.3.2;ok;iifname "eth0" tcp dport >= 80 tcp dport <= 90 dnat 192.168.3.2
iifname eth0 tcp dport != 80-90 dnat 192.168.3.2;ok;iifname "eth0" tcp dport < 80 tcp dport > 90 dnat 192.168.3.2
iifname eth0 tcp dport {80, 90, 23} dnat 192.168.3.2;ok
- iifname eth0 tcp dport != {80, 90, 23} dnat 192.168.3.2;ok

iifname eth0 tcp sport 23-34 snat 192.168.3.2;ok;iifname "eth0" tcp sport >= 23 tcp sport <= 34 snat 192.168.3.2

- iifname eth0 tcp dport != {80, 90, 23} dnat 192.168.3.2;ok
# BUG: invalid expression type set
# nft: src/evaluate.c:975: expr_evaluate_relational: Assertion '0' failed.

iifname eth0 tcp dport != 23-34 dnat 192.168.3.2;ok;iifname "eth0" tcp dport < 23 tcp dport > 34 dnat 192.168.3.2
