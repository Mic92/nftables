*ip;test-ip4
*ip6;test-ip6
*inet;test-inet
:input;type filter hook input priority 0

tcp dport 22;ok
tcp dport != 233;ok
tcp dport 33-45;ok;tcp dport >= 33 tcp dport <= 45
tcp dport != 33-45;ok;tcp dport < 33 tcp dport > 45
tcp dport { 33, 55, 67, 88};ok
- tcp dport != { 33, 55, 67, 88};ok
tcp dport { 33-55};ok
- tcp dport != { 33-55};ok
tcp dport {telnet, http, https} accept;ok;tcp dport { 443, 23, 80} accept
tcp dport vmap { 22 : accept, 23 : drop };ok
tcp dport vmap { 25:accept, 28:drop };ok
tcp dport { 22, 53, 80, 110 };ok
- tcp dport != { 22, 53, 80, 110 };ok
# BUG: invalid expression type set
# nft: src/evaluate.c:975: expr_evaluate_relational: Assertion '0' failed.

tcp sport 22;ok
tcp sport != 233;ok
tcp sport 33-45;ok;tcp sport >= 33 tcp sport <= 45
tcp sport != 33-45;ok;tcp sport < 33 tcp sport > 45
tcp sport { 33, 55, 67, 88};ok
- tcp sport != { 33, 55, 67, 88};ok
tcp sport { 33-55};ok
- tcp sport != { 33-55};ok
tcp sport vmap { 25:accept, 28:drop };ok

tcp sport 8080 drop;ok
tcp sport 1024 tcp dport 22;ok
tcp sport 1024 tcp dport 22 tcp sequence 0;ok

tcp sequence 0 tcp sport 1024 tcp dport 22;ok;tcp sport 1024 tcp dport 22 tcp sequence 0
tcp sequence 0 tcp sport { 1024, 1022} tcp dport 22;ok

tcp sequence 22;ok
tcp sequence != 233;ok
tcp sequence 33-45;ok;tcp sequence >= 33 tcp sequence <= 45
tcp sequence != 33-45;ok;tcp sequence < 33 tcp sequence > 45
tcp sequence { 33, 55, 67, 88};ok
- tcp sequence != { 33, 55, 67, 88};ok
tcp sequence { 33-55};ok
- tcp sequence != { 33-55};ok

tcp ackseq 42949672 drop;ok
tcp ackseq 22;ok
tcp ackseq != 233;ok
tcp ackseq 33-45;ok;tcp ackseq >= 33 tcp ackseq <= 45
tcp ackseq != 33-45;ok;tcp ackseq < 33 tcp ackseq > 45
tcp ackseq { 33, 55, 67, 88};ok
- tcp ackseq != { 33, 55, 67, 88};ok
tcp ackseq { 33-55};ok
- tcp ackseq != { 33-55};ok

- tcp doff 22;ok
- tcp doff != 233;ok
- tcp doff 33-45;ok
- tcp doff != 33-45;ok
- tcp doff { 33, 55, 67, 88};ok
- tcp doff != { 33, 55, 67, 88};ok
- tcp doff { 33-55};ok
- tcp doff != { 33-55};ok

# BUG reserved
# BUG: It is accepted but it is not shown then. tcp reserver

tcp flags { fin, syn, rst, psh, ack, urg, ecn, cwr} drop;ok
- tcp flags != { fin, urg, ecn, cwr} drop;ok
tcp flags cwr;ok
tcp flags != cwr;ok

tcp window 22222;ok
tcp window 22;ok
tcp window != 233;ok
tcp window 33-45;ok;tcp window >= 33 tcp window <= 45
tcp window != 33-45;ok;tcp window < 33 tcp window > 45
tcp window { 33, 55, 67, 88};ok
- tcp window != { 33, 55, 67, 88};ok
tcp window { 33-55};ok
- tcp window != { 33-55};ok

tcp checksum 23456 log drop;ok
tcp checksum 22;ok
tcp checksum != 233;ok
tcp checksum 33-45;ok;tcp checksum >= 33 tcp checksum <= 45
tcp checksum != 33-45;ok;tcp checksum < 33 tcp checksum > 45
tcp checksum { 33, 55, 67, 88};ok
- tcp checksum != { 33, 55, 67, 88};ok
tcp checksum { 33-55};ok
- tcp checksum != { 33-55};ok

tcp urgptr 1234 accept;ok
tcp urgptr 22;ok
tcp urgptr != 233;ok
tcp urgptr 33-45;ok;tcp urgptr >= 33 tcp urgptr <= 45
tcp urgptr != 33-45;ok;tcp urgptr < 33 tcp urgptr > 45
tcp urgptr { 33, 55, 67, 88};ok
- tcp urgptr != { 33, 55, 67, 88};ok
tcp urgptr { 33-55};ok
- tcp urgptr != { 33-55};ok
