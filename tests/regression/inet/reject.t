*inet;test-inet
:input;type filter hook input priority 0

# The output is specific for inet family
reject with icmp type host-unreachable;ok;meta nfproto ipv4 reject with icmp type host-unreachable
reject with icmp type net-unreachable;ok;meta nfproto ipv4 reject with icmp type net-unreachable
reject with icmp type prot-unreachable;ok;meta nfproto ipv4 reject with icmp type prot-unreachable
reject with icmp type port-unreachable;ok;meta nfproto ipv4 reject
reject with icmp type net-prohibited;ok;meta nfproto ipv4 reject with icmp type net-prohibited
reject with icmp type host-prohibited;ok;meta nfproto ipv4 reject with icmp type host-prohibited
reject with icmp type admin-prohibited;ok;meta nfproto ipv4 reject with icmp type admin-prohibited

reject with icmpv6 type no-route;ok;meta nfproto ipv6 reject with icmpv6 type no-route
reject with icmpv6 type admin-prohibited;ok;meta nfproto ipv6 reject with icmpv6 type admin-prohibited
reject with icmpv6 type addr-unreachable;ok;meta nfproto ipv6 reject with icmpv6 type addr-unreachable
reject with icmpv6 type port-unreachable;ok;meta nfproto ipv6 reject

reject with tcp reset;ok;meta l4proto 6 reject with tcp reset

reject;ok
meta nfproto ipv4 reject;ok
meta nfproto ipv6 reject;ok

reject with icmpx type host-unreachable;ok
reject with icmpx type no-route;ok
reject with icmpx type admin-prohibited;ok
reject with icmpx type port-unreachable;ok;reject

meta nfproto ipv4 reject with icmp type host-unreachable;ok
meta nfproto ipv6 reject with icmpv6 type no-route;ok

meta nfproto ipv6 reject with icmp type host-unreachable;fail
meta nfproto ipv4 ip protocol icmp reject with icmpv6 type no-route;fail
meta nfproto ipv6 ip protocol icmp reject with icmp type host-unreachable;fail
meta l4proto udp reject with tcp reset;fail
