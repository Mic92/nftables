*ip6;test-ip6
*inet;test-inet
:input;type filter hook input priority 0

ip6 saddr vmap { abcd::3 : accept };ok
ip6 saddr 1234:1234:1234:1234:1234:1234:1234:1234:1234;fail

# Ipv6 address combinations
# from src/scanner.l
ip6 saddr vmap { 1234:1234:1234:1234:1234:1234:1234:1234 : accept};ok
ip6 saddr vmap { ::1234:1234:1234:1234:1234:1234:1234 : accept};ok
ip6 saddr vmap { 1234::1234:1234:1234:1234:1234:1234 : accept};ok
ip6 saddr vmap { 1234:1234::1234:1234:1234:1234:1234 : accept};ok
ip6 saddr vmap { 1234:1234:1234::1234:1234:1234:1234 : accept};ok
ip6 saddr vmap { 1234:1234:1234:1234::1234:1234:1234 : accept};ok
ip6 saddr vmap { 1234:1234:1234:1234:1234::1234:1234 : accept};ok
ip6 saddr vmap { 1234:1234:1234:1234:1234:1234::1234 : accept};ok
ip6 saddr vmap { 1234:1234:1234:1234:1234:1234:1234:: : accept};ok
ip6 saddr vmap { ::1234:1234:1234:1234:1234:1234 : accept};ok
ip6 saddr vmap { 1234::1234:1234:1234:1234:1234 : accept};ok
ip6 saddr vmap { 1234:1234::1234:1234:1234:1234 : accept};ok
ip6 saddr vmap { 1234:1234:1234::1234:1234:1234 : accept};ok
ip6 saddr vmap { 1234:1234:1234:1234::1234:1234 : accept};ok
ip6 saddr vmap { 1234:1234:1234:1234:1234::1234 : accept};ok
ip6 saddr vmap { 1234:1234:1234:1234:1234:1234:: : accept};ok
ip6 saddr vmap { ::1234:1234:1234:1234:1234 : accept};ok
ip6 saddr vmap { 1234::1234:1234:1234:1234 : accept};ok
ip6 saddr vmap { 1234:1234::1234:1234:1234 : accept};ok
ip6 saddr vmap { 1234:1234:1234::1234:1234 : accept};ok
ip6 saddr vmap { 1234:1234:1234:1234::1234 : accept};ok
ip6 saddr vmap { 1234:1234:1234:1234:1234::  : accept};ok
ip6 saddr vmap { ::1234:1234:1234:1234 : accept};ok
ip6 saddr vmap { 1234::1234:1234:1234 : accept};ok
ip6 saddr vmap { 1234:1234::1234:1234 : accept};ok
ip6 saddr vmap { 1234:1234:1234::1234 : accept};ok
ip6 saddr vmap { 1234:1234:1234:1234:: : accept};ok
ip6 saddr vmap { ::1234:1234:1234 : accept};ok
ip6 saddr vmap { 1234::1234:1234 : accept};ok
ip6 saddr vmap { 1234:1234::1234 : accept};ok
ip6 saddr vmap { 1234:1234:1234:: : accept};ok
ip6 saddr vmap { ::1234:1234 : accept};ok
ip6 saddr vmap { 1234::1234 : accept};ok
ip6 saddr vmap { 1234:1234:: : accept};ok
ip6 saddr vmap { ::1234 : accept};ok
ip6 saddr vmap { 1234:: : accept};ok
ip6 saddr vmap { ::/64 : accept};ok

ip6 saddr vmap {1234:1234:1234:1234:1234:1234:aaaa:: : accept, ::aaaa : drop};ok
ip6 saddr vmap {1234:1234:1234:1234:1234:1234:aaaa:::accept, ::bbbb : drop};ok
ip6 saddr vmap {1234:1234:1234:1234:1234:1234:aaaa:::accept,::cccc : drop};ok
ip6 saddr vmap {1234:1234:1234:1234:1234:1234:aaaa:::accept,::dddd: drop};ok

# rule without comma:
filter-input ip6 saddr vmap { 1234:1234:1234:1234:1234:1234:bbbb:::accept::adda : drop};fail
