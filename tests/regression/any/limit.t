*ip;test-ip4
*ip6;test-ip6
*inet;test-inet
*arp;test-arp
*bridge;test-bridge
:output;type filter hook output priority 0

limit rate 400/minute;ok
limit rate 20/second;ok
limit rate 400/hour;ok
limit rate 400/week;ok
limit rate 40/day;ok
