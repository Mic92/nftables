*ip;test-ip4
*ip6;test-ip6
*inet;test-inet
:input;type filter hook input priority 0

dccp sport 21-35;ok;dccp sport >= 21 dccp sport <= 35
dccp sport != 21-35;ok;dccp sport < 21 dccp sport > 35
dccp sport {23, 24, 25};ok;dccp sport { 23, 24, 25}
- dccp sport != { 27, 34};ok
# BUG: invalid expression type set
# nft: src/evaluate.c:975: expr_evaluate_relational: Assertion '0' failed.

dccp sport { ftp-data - re-mail-ck};ok;dccp sport { 20-50}
dccp sport ftp-data - re-mail-ck;ok;dccp sport >= 20 dccp sport <= 50
dccp sport { 20-50};ok
- dccp sport != {27-34};ok
# dccp sport != {27-34};ok
# BUG: invalid expression type set
# nft: src/evaluate.c:975: expr_evaluate_relational: Assertion '0' failed.

# dccp dport 21-35;ok
# dccp dport != 21-35;ok
dccp dport {23, 24, 25};ok
# dccp dport != {27, 34};ok
dccp dport { 20-50};ok
# dccp dport != {27-34};ok

# BUG dccp type
# dccp type {request, response, data, ack, dataack, closereq, close, reset, sync, syncack};ok
# dccp type != {request, response, data, ack, dataack, closereq, close, reset, sync, syncack};ok
# dccp type request;ok
# dccp type != request;ok
