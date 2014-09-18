*ip;test-ip4
*ip;test-ip6
*ip;test-inet
:input;type filter hook input priority 0

udp sport 80 accept;ok
udp sport != 60 accept;ok
udp sport 50-70 accept;ok;udp sport >= 50 udp sport <= 70 accept
udp sport != 50-60 accept;ok;udp sport < 50 udp sport > 60 accept
udp sport { 49, 50} drop;ok;udp sport { 49, 50} drop
- udp sport != { 50, 60} accept;ok
# BUG: invalid expression type set
# nft: src/evaluate.c:975: expr_evaluate_relational: Assertion '0' failed.
udp sport { 12-40};ok
- udp sport != { 13-24};ok

udp dport 80 accept;ok
udp dport != 60 accept;ok
udp dport 70-75 accept;ok;udp dport >= 70 udp dport <= 75 accept
udp dport != 50-60 accept;ok;udp dport < 50 udp dport > 60 accept
udp dport { 49, 50} drop;ok
- udp dport != { 50, 60} accept;ok
# BUG: invalid expression type set
# nft: src/evaluate.c:975: expr_evaluate_relational: Assertion '0' failed.
udp dport { 70-75} accept;ok;udp dport { 70-75} accept
- udp dport != { 50-60} accept;ok

udp length 6666;ok
udp length != 6666;ok
udp length 50-65 accept;ok;udp length >= 50 udp length <= 65 accept
udp length != 50-65 accept;ok;udp length < 50 udp length > 65 accept
udp length { 50, 65} accept;ok
- udp length != { 50, 65} accept;ok
udp length { 35-50};ok
- udp length != { 35-50};ok

udp checksum 6666 drop;ok
- udp checksum != { 444, 555} accept;ok
# BUG: invalid expression type set
# nft: src/evaluate.c:975: expr_evaluate_relational: Assertion '0' failed.

udp checksum 22;ok
udp checksum != 233;ok
udp checksum 33-45;ok;udp checksum >= 33 udp checksum <= 45
udp checksum != 33-45;ok;udp checksum < 33 udp checksum > 45
udp checksum { 33, 55, 67, 88};ok
- udp checksum != { 33, 55, 67, 88};ok
udp checksum { 33-55};ok
- udp checksum != { 33-55};ok
