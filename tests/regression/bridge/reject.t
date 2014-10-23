*bridge;test-bridge
:input;type filter hook input priority 0

# The output is specific for bridge family
reject with icmp type host-unreachable;ok;ether type ip reject with icmp type host-unreachable
reject with icmp type net-unreachable;ok;ether type ip reject with icmp type net-unreachable
reject with icmp type prot-unreachable;ok;ether type ip reject with icmp type prot-unreachable
reject with icmp type port-unreachable;ok;ether type ip reject
reject with icmp type net-prohibited;ok;ether type ip reject with icmp type net-prohibited
reject with icmp type host-prohibited;ok;ether type ip reject with icmp type host-prohibited
reject with icmp type admin-prohibited;ok;ether type ip reject with icmp type admin-prohibited

reject with icmpv6 type no-route;ok;ether type ip6 reject with icmpv6 type no-route
reject with icmpv6 type admin-prohibited;ok;ether type ip6 reject with icmpv6 type admin-prohibited
reject with icmpv6 type addr-unreachable;ok;ether type ip6 reject with icmpv6 type addr-unreachable
reject with icmpv6 type port-unreachable;ok;ether type ip6 reject

ip protocol tcp reject with tcp reset;ok;ip protocol 6 reject with tcp reset

reject;ok
ether type ip reject;ok
ether type ip6 reject;ok

reject with icmpx type host-unreachable;ok
reject with icmpx type no-route;ok
reject with icmpx type admin-prohibited;ok
reject with icmpx type port-unreachable;ok;reject

ether type ipv6 reject with icmp type host-unreachable;fail
ether type ip6 reject with icmp type host-unreachable;fail
ether type ip reject with icmpv6 type no-route;fail
ether type vlan reject;fail
ether type arp reject;fail
ether type vlan reject;fail
ether type arp reject;fail
ether type vlan reject with tcp reset;fail
ether type arp reject with tcp reset;fail
ip protocol udp reject with tcp reset;fail
