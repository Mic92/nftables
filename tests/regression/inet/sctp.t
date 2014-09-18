*ip;test-ip4
*ip6;test-ip6
*inet;test-inet
:input;type filter hook input priority 0

sctp sport 23;ok
sctp sport != 23;ok
sctp sport 23-44;ok;sctp sport >= 23 sctp sport <= 44
sctp sport != 23-44;ok;sctp sport < 23 sctp sport > 44
sctp sport { 23, 24, 25};ok
- sctp sport != { 23, 24, 25};ok
sctp sport { 23-44};ok
- sctp sport != { 23-44};ok
# BUG: invalid expression type set
# nft: src/evaluate.c:975: expr_evaluate_relational: Assertion '0' failed.

sctp dport 23;ok
sctp dport != 23;ok
sctp dport 23-44;ok;sctp dport >= 23 sctp dport <= 44
sctp dport != 23-44;ok;sctp dport < 23 sctp dport > 44
sctp dport { 23, 24, 25};ok
- sctp dport != { 23, 24, 25};ok
sctp dport { 23-44};ok
- sctp dport != { 23-44};ok

sctp checksum 1111;ok
sctp checksum != 11;ok
sctp checksum 21-333;ok;sctp checksum >= 21 sctp checksum <= 333
sctp checksum != 32-111;ok;sctp checksum < 32 sctp checksum > 111
sctp checksum { 22, 33, 44};ok
- sctp checksum != { 22, 33, 44};ok
sctp checksum { 22-44};ok
- sctp checksum != { 22-44};ok

sctp vtag 22;ok
sctp vtag != 233;ok
sctp vtag 33-45;ok;sctp vtag >= 33 sctp vtag <= 45
sctp vtag != 33-45;ok;sctp vtag < 33 sctp vtag > 45
sctp vtag {33, 55, 67, 88};ok
- sctp vtag != {33, 55, 67, 88};ok
sctp vtag { 33-55};ok
- sctp vtag != { 33-55};ok
