*ip;test-ip4
:output;type nat hook output priority 0

# without arguments
udp dport 53 redirect;ok

# nf_nat flags combination
udp dport 53 redirect random;ok
udp dport 53 redirect random,persistent;ok
udp dport 53 redirect random,persistent,fully-random;ok;udp dport 53 redirect random,fully-random,persistent
udp dport 53 redirect random,fully-random;ok
udp dport 53 redirect random,fully-random,persistent;ok
udp dport 53 redirect persistent;ok
udp dport 53 redirect persistent,random;ok;udp dport 53 redirect random,persistent
udp dport 53 redirect persistent,random,fully-random;ok;udp dport 53 redirect random,fully-random,persistent
udp dport 53 redirect persistent,fully-random;ok;udp dport 53 redirect fully-random,persistent
udp dport 53 redirect persistent,fully-random,random;ok;udp dport 53 redirect random,fully-random,persistent

# port specification
tcp dport 22 redirect :22;ok
udp dport 1234 redirect :4321;ok
ip daddr 172.16.0.1 udp dport 9998 redirect :6515;ok
tcp dport 39128 redirect :993;ok
redirect :1234;fail
redirect :12341111;fail

# both port and nf_nat flags
tcp dport 9128 redirect :993 random;ok
tcp dport 9128 redirect :993 fully-random;ok
tcp dport 9128 redirect :123 persistent;ok
tcp dport 9128 redirect :123 random,persistent;ok

# nf_nat flags is the last argument
udp dport 1234 redirect random :123;fail
udp dport 21234 redirect persistent,fully-random :431;fail

# redirect is a terminal statement
tcp dport 22 redirect counter packets 0 bytes 0 accept;fail
tcp sport 22 redirect accept;fail
ip saddr 10.1.1.1 redirect drop;fail

# redirect with sets
tcp dport {1,2,3,4,5,6,7,8,101,202,303,1001,2002,3003} redirect;ok
ip daddr 10.0.0.0-10.2.3.4 udp dport 53 counter packets 0 bytes 0 redirect;ok;ip daddr >= 10.0.0.0 ip daddr <= 10.2.3.4 udp dport 53 counter packets 0 bytes 0 redirect
iifname eth0 ct state new,established tcp dport vmap {22 : drop, 222 : drop } redirect;ok
