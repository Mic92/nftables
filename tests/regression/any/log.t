*ip;test-ip4
*ip6;test-ip6
*inet;test-inet
*arp;test-arp
*bridge;test-bridge
:output;type filter hook output priority 0

log;ok
log level emerg;ok
log level alert;ok
log level crit;ok
log level err;ok
log level warn;ok;log
log level notice;ok
log level info;ok
log level debug;ok

log level emerg group 2;fail
log level alert group 2 prefix "log test2";fail

log prefix aaaaa-aaaaaa group 2 snaplen 33;ok;log prefix "aaaaa-aaaaaa" group 2 snaplen 33
# TODO: Add an exception: 'queue-threshold' attribute needs 'group' attribute
# The correct rule is log group 2 queue-threshold 2
log group 2 queue-threshold 2;ok
log group 2 snaplen 33;ok
log group 2 prefix \"nft-test: \";ok;log prefix "nft-test: " group 2
