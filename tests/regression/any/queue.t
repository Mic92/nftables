*ip;test-ip4
*ip6;test-ip6
*inet;test-inet
*arp;test-arp
*bridge;test-bridge

:output;type filter hook output priority 0

queue;ok;queue num 0
queue num 2;ok
queue num 2-3;ok
- queue num {3, 4, 6};ok
queue num 4-5 fanout bypass;ok;queue num 4-5 bypass,fanout
queue num 4-5 fanout;ok
queue num 4-5 bypass;ok
