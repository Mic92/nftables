*ip;test-ip4
*ip6;test-ip6
*inet;test-inet
:input;type filter hook input priority 0

udplite sport 80 accept;ok
udplite sport != 60 accept;ok
udplite sport 50-70 accept;ok;udplite sport >= 50 udplite sport <= 70 accept
udplite sport != 50-60 accept;ok;udplite sport < 50 udplite sport > 60 accept
udplite sport { 49, 50} drop;ok;udplite sport { 49, 50} drop
- udplite sport != { 50, 60} accept;ok
udplite sport { 12-40};ok
- udplite sport != { 13-24};ok

udplite dport 80 accept;ok
udplite dport != 60 accept;ok
udplite dport 70-75 accept;ok;udplite dport >= 70 udplite dport <= 75 accept
udplite dport != 50-60 accept;ok;udplite dport < 50 udplite dport > 60 accept
udplite dport { 49, 50} drop;ok;udplite dport { 49, 50} drop
- udplite dport != { 50, 60} accept;ok
udplite dport { 70-75} accept;ok;udplite dport { 70-75} accept
- udplite dport != { 50-60} accept;ok

- udplite csumcov 6666;ok
- udplite csumcov != 6666;ok
- udplite csumcov 50-65 accept;ok
- udplite csumcov != 50-65 accept;ok
- udplite csumcov { 50, 65} accept;ok
- udplite csumcov != { 50, 65} accept;ok
- udplite csumcov { 35-50};ok
- udplite csumcov != { 35-50};ok

udplite checksum 6666 drop;ok
- udplite checksum != { 444, 555} accept;ok
udplite checksum 22;ok
udplite checksum != 233;ok
udplite checksum 33-45;ok;udplite checksum >= 33 udplite checksum <= 45
udplite checksum != 33-45;ok;udplite checksum < 33 udplite checksum > 45
udplite checksum { 33, 55, 67, 88};ok
- udplite checksum != { 33, 55, 67, 88};ok
udplite checksum { 33-55};ok
- udplite checksum != { 33-55};ok
