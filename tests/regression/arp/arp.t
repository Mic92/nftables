*arp;test-arp
# filter chains available are: input, output, forward
:input;type filter hook input priority 0

arp htype 1;ok
arp htype != 1;ok
arp htype 22;ok
arp htype != 233;ok
arp htype 33-45;ok;arp htype >= 33 arp htype <= 45
arp htype != 33-45;ok;arp htype < 33 arp htype > 45
arp htype { 33, 55, 67, 88};ok
- arp htype != { 33, 55, 67, 88};ok
arp htype { 33-55};ok
- arp htype != { 33-55};ok

arp ptype 0x0800;ok

arp hlen 22;ok
arp hlen != 233;ok
arp hlen 33-45;ok;arp hlen >= 33 arp hlen <= 45
arp hlen != 33-45;ok;arp hlen < 33 arp hlen > 45
arp hlen { 33, 55, 67, 88};ok
- arp hlen != { 33, 55, 67, 88};ok
arp hlen { 33-55};ok
- arp hlen != { 33-55};ok

arp plen 22;ok
arp plen != 233;ok
arp plen 33-45;ok;arp plen >= 33 arp plen <= 45
arp plen != 33-45;ok;arp plen < 33 arp plen > 45
arp plen { 33, 55, 67, 88};ok
- arp plen != { 33, 55, 67, 88};ok
arp plen { 33-55};ok
- arp plen != {33-55};ok

arp operation {nak, inreply, inrequest, rreply, rrequest, reply, request};ok
- arp operation != {nak, inreply, inrequest, rreply, rrequest, reply, request};ok
arp operation request;ok
arp operation reply;ok
arp operation rrequest;ok
arp operation rreply;ok
arp operation inrequest;ok
arp operation inreply;ok
arp operation nak;ok
arp operation reply;ok
arp operation != request;ok
arp operation != reply;ok
arp operation != rrequest;ok
arp operation != rreply;ok
arp operation != inrequest;ok
arp operation != inreply;ok
arp operation != nak;ok
arp operation != reply;ok
