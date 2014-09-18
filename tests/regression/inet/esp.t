*ip;test-ip4
*ip6;test-ip6
*inet;test-inet
:input;type filter hook input priority 0

esp spi 100;ok
esp spi != 100;ok
esp spi 111-222;ok;esp spi >= 111 esp spi <= 222
esp spi != 111-222;ok;esp spi < 111 esp spi > 222
esp spi { 100, 102};ok
- esp spi != { 100, 102};ok
esp spi { 100-102};ok
- esp spi {100-102};ok

esp sequence 22;ok
esp sequence 22-24;ok;esp sequence >= 22 esp sequence <= 24
esp sequence != 22-24;ok;esp sequence < 22 esp sequence > 24
esp sequence { 22, 24};ok
- esp sequence != { 22, 24};ok
# BUG: invalid expression type set
# nft: src/evaluate.c:975: expr_evaluate_relational: Assertion '0' failed.
esp sequence { 22-25};ok
- esp sequence != { 22-25};ok
