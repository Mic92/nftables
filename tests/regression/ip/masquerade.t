*ip;test-ip4
:output;type nat hook output priority 0

# nf_nat flags combination
udp dport 53 masquerade;ok
udp dport 53 masquerade random;ok
udp dport 53 masquerade random,persistent;ok
udp dport 53 masquerade random,persistent,random-fully;ok;udp dport 53 masquerade random,random-fully,persistent
udp dport 53 masquerade random,random-fully;ok
udp dport 53 masquerade random,random-fully,persistent;ok
udp dport 53 masquerade persistent;ok
udp dport 53 masquerade persistent,random;ok;udp dport 53 masquerade random,persistent
udp dport 53 masquerade persistent,random,random-fully;ok;udp dport 53 masquerade random,random-fully,persistent
udp dport 53 masquerade persistent,random-fully;ok;udp dport 53 masquerade random-fully,persistent
udp dport 53 masquerade persistent,random-fully,random;ok;udp dport 53 masquerade random,random-fully,persistent

# masquerade is a terminal statement
tcp dport 22 masquerade counter packets 0 bytes 0 accept;fail
tcp sport 22 masquerade accept;fail
ip saddr 10.1.1.1 masquerade drop;fail

# masquerade with sets
tcp dport { 1,2,3,4,5,6,7,8,101,202,303,1001,2002,3003} masquerade;ok
ip daddr 10.0.0.0-10.2.3.4 udp dport 53 counter packets 0 bytes 0 masquerade;ok;ip daddr >= 10.0.0.0 ip daddr <= 10.2.3.4 udp dport 53 counter packets 0 bytes 0 masquerade
iifname eth0 ct state new,established tcp dport vmap {22 : drop, 222 : drop } masquerade;ok
