*ip;test-ip4
:output;type filter hook output priority 0

reject;ok
reject with icmp type host-unreachable;ok
reject with icmp type net-unreachable;ok
reject with icmp type prot-unreachable;ok
reject with icmp type port-unreachable;ok;reject
reject with icmp type net-prohibited;ok
reject with icmp type host-prohibited;ok
reject with icmp type admin-prohibited;ok

reject with icmp type no-route;fail
reject with icmpv6 type no-route;fail
