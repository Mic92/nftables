*ip;test-ip4
*ip6;test-ip6
*inet;test-inet
:input;type filter hook input priority 0

# nexthdr Bug to list table.

- ah nexthdr esp;ok
- ah nexthdr ah;ok
- ah nexthdr comp;ok
- ah nexthdr udp;ok
- ah nexthdr udplite;ok
- ah nexthdr tcp;ok
- ah nexthdr dccp;ok
- ah nexthdr sctp;ok

- ah nexthdr { esp, ah, comp, udp, udplite, tcp, dccp, sctp};ok;ah nexthdr { 6, 132, 50, 17, 136, 33, 51, 108}
- ah nexthdr != { esp, ah, comp, udp, udplite, tcp, dccp, sctp};ok

ah hdrlength 11-23;ok;ah hdrlength >= 11 ah hdrlength <= 23
ah hdrlength != 11-23;ok;ah hdrlength < 11 ah hdrlength > 23
ah hdrlength { 11-23};ok
- ah hdrlength != { 11-23};ok
ah hdrlength {11, 23, 44 };ok
- ah hdrlength != {11-23 };ok

ah reserved 22;ok
ah reserved != 233;ok
ah reserved 33-45;ok;ah reserved >= 33 ah reserved <= 45
ah reserved != 33-45;ok;ah reserved < 33 ah reserved > 45
ah reserved {23, 100};ok
- ah reserved != {33, 55, 67, 88};ok
ah reserved { 33-55};ok
- ah reserved != { 33-55};ok

ah spi 111;ok
ah spi != 111;ok
ah spi 111-222;ok;ah spi >= 111 ah spi <= 222
ah spi != 111-222;ok;ah spi < 111 ah spi > 222
ah spi {111, 122};ok
- ah spi != {111, 122};ok
# BUG: invalid expression type set
# nft: src/evaluate.c:975: expr_evaluate_relational: Assertion '0' failed.

ah spi { 111-122};ok
- ah spi != { 111-122};ok
# BUG: invalid expression type set
# nft: src/evaluate.c:975: expr_evaluate_relational: Assertion '0' failed.

# sequence
ah sequence 123;ok
ah sequence != 123;ok
ah sequence {23, 25, 33};ok
- ah sequence != {23, 25, 33};ok
ah sequence { 23-33};ok
- ah sequence != { 33-44};ok
ah sequence 23-33;ok;ah sequence >= 23 ah sequence <= 33
ah sequence != 23-33;ok;ah sequence < 23 ah sequence > 33
