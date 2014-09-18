*ip6;test-ip6
*inet;test-inet
:input;type filter hook input priority 0

# BUG: Problem with version, priority
# <cmdline>:1:1-38: Error: Could not process rule: Invalid argument
# add rule ip6 test6 input ip6 version 1
# ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- ip6 version 6;ok
- ip6 priority 3;ok

# $ sudo nft add rule ip6 test6 input ip6 priority 33
# <cmdline>:1:39-40: Error: Value 33 exceeds valid range 0-15
# $ sudo nft add rule ip6 test6 input ip6 priority 3
# <cmdline>:1:1-39: Error: Could not process rule: Invalid argument
# add rule ip6 test6 input ip6 priority 3
#^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

ip6 flowlabel 22;ok
ip6 flowlabel != 233;ok
- ip6 flowlabel 33-45;ok
- ip6 flowlabel != 33-45;ok
ip6 flowlabel { 33, 55, 67, 88};ok
# BUG ip6 flowlabel { 5046528, 2883584, 13522432 }
- ip6 flowlabel != { 33, 55, 67, 88};ok
ip6 flowlabel { 33-55};ok
- ip6 flowlabel != { 33-55};ok

ip6 length 22;ok
ip6 length != 233;ok
ip6 length 33-45;ok;ip6 length >= 33 ip6 length <= 45
ip6 length != 33-45;ok;ip6 length < 33 ip6 length > 45
- ip6 length { 33, 55, 67, 88};ok
- ip6 length != {33, 55, 67, 88};ok
ip6 length { 33-55};ok
- ip6 length != { 33-55};ok

ip6 nexthdr {udp, ah, comp, udplite, tcp, dccp, sctp} log;ok;ip6 nexthdr { 132, 51, 108, 136, 17, 33, 6} log
ip6 nexthdr {esp, ah, comp, udp, udplite, tcp, dccp, sctp, icmpv6};ok;ip6 nexthdr { 6, 136, 108, 33, 50, 17, 132, 58, 51}
- ip6 nexthdr != {esp, ah, comp, udp, udplite, tcp, dccp, sctp, icmpv6};ok
ip6 nexthdr esp;ok;ip6 nexthdr 50
ip6 nexthdr != esp;ok;ip6 nexthdr != 50
ip6 nexthdr { 33-44};ok
- p6 nexthdr != { 33-44};ok
ip6 nexthdr 33-44;ok;ip6 nexthdr >= 33 ip6 nexthdr <= 44
ip6 nexthdr != 33-44;ok;ip6 nexthdr < 33 ip6 nexthdr > 44

ip6 hoplimit 1 log;ok
ip6 hoplimit != 233;ok
ip6 hoplimit 33-45;ok;ip6 hoplimit >= 33 ip6 hoplimit <= 45
ip6 hoplimit != 33-45;ok;ip6 hoplimit < 33 ip6 hoplimit > 45
ip6 hoplimit {33, 55, 67, 88};ok
- ip6 hoplimit != {33, 55, 67, 88};ok
ip6 hoplimit {33-55};ok
- ip6 hoplimit != {33-55};ok

# from src/scanner.l
# v680		(({hex4}:){7}{hex4})
ip6 saddr 1234:1234:1234:1234:1234:1234:1234:1234;ok
# v670		((:)(:{hex4}{7}))
ip6 saddr ::1234:1234:1234:1234:1234:1234:1234;ok
# v671		((({hex4}:){1})(:{hex4}{6}))
ip6 saddr 1234::1234:1234:1234:1234:1234:1234;ok
# v672		((({hex4}:){2})(:{hex4}{5}))
ip6 saddr 1234:1234::1234:1234:1234:1234:1234;ok
# v673		((({hex4}:){3})(:{hex4}{4}))
ip6 saddr 1234:1234:1234::1234:1234:1234:1234;ok
# v674		((({hex4}:){4})(:{hex4}{3}))
ip6 saddr 1234:1234:1234:1234::1234:1234:1234;ok
# v675		((({hex4}:){5})(:{hex4}{2}))
ip6 saddr 1234:1234:1234:1234:1234::1234:1234;ok
# v676		((({hex4}:){6})(:{hex4}{1}))
ip6 saddr 1234:1234:1234:1234:1234:1234::1234;ok
# v677		((({hex4}:){7})(:))
ip6 saddr 1234:1234:1234:1234:1234:1234:1234::;ok
# v67		({v670}|{v671}|{v672}|{v673}|{v674}|{v675}|{v676}|{v677})
# v660		((:)(:{hex4}{6}))
ip6 saddr ::1234:1234:1234:1234:1234:1234;ok
# v661		((({hex4}:){1})(:{hex4}{5}))
ip6 saddr 1234::1234:1234:1234:1234:1234;ok
# v662		((({hex4}:){2})(:{hex4}{4}))
ip6 saddr 1234:1234::1234:1234:1234:1234;ok
# v663		((({hex4}:){3})(:{hex4}{3}))
ip6 saddr 1234:1234:1234::1234:1234:1234;ok
# v664		((({hex4}:){4})(:{hex4}{2}))
ip6 saddr 1234:1234:1234:1234::1234:1234;ok
# v665		((({hex4}:){5})(:{hex4}{1}))
ip6 saddr 1234:1234:1234:1234:1234::1234;ok
# v666		((({hex4}:){6})(:))
ip6 saddr 1234:1234:1234:1234:1234:1234::;ok
# v66		({v660}|{v661}|{v662}|{v663}|{v664}|{v665}|{v666})
# v650		((:)(:{hex4}{5}))
ip6 saddr ::1234:1234:1234:1234:1234;ok
# v651		((({hex4}:){1})(:{hex4}{4}))
ip6 saddr 1234::1234:1234:1234:1234;ok
# v652		((({hex4}:){2})(:{hex4}{3}))
ip6 saddr 1234:1234::1234:1234:1234;ok
# v653		((({hex4}:){3})(:{hex4}{2}))
ip6 saddr 1234:1234:1234::1234:1234;ok
# v654		((({hex4}:){4})(:{hex4}{1}))
ip6 saddr 1234:1234:1234:1234::1234;ok
# v655		((({hex4}:){5})(:))
ip6 saddr 1234:1234:1234:1234:1234::;ok
# v65		({v650}|{v651}|{v652}|{v653}|{v654}|{v655})
# v640		((:)(:{hex4}{4}))
ip6 saddr ::1234:1234:1234:1234;ok
# v641		((({hex4}:){1})(:{hex4}{3}))
ip6 saddr 1234::1234:1234:1234;ok
# v642		((({hex4}:){2})(:{hex4}{2}))
ip6 saddr 1234:1234::1234:1234;ok
# v643		((({hex4}:){3})(:{hex4}{1}))
ip6 saddr 1234:1234:1234::1234;ok
# v644		((({hex4}:){4})(:))
ip6 saddr 1234:1234:1234:1234::;ok
# v64		({v640}|{v641}|{v642}|{v643}|{v644})
# v630		((:)(:{hex4}{3}))
ip6 saddr ::1234:1234:1234;ok
# v631		((({hex4}:){1})(:{hex4}{2}))
ip6 saddr 1234::1234:1234;ok
# v632		((({hex4}:){2})(:{hex4}{1}))
ip6 saddr 1234:1234::1234;ok
# v633		((({hex4}:){3})(:))
ip6 saddr 1234:1234:1234::;ok
# v63		({v630}|{v631}|{v632}|{v633})
# v620		((:)(:{hex4}{2}))
ip6 saddr ::1234:1234;ok
# v621		((({hex4}:){1})(:{hex4}{1}))
ip6 saddr 1234::1234;ok
# v622		((({hex4}:){2})(:))
ip6 saddr 1234:1234::;ok
# v62		({v620}|{v621}|{v622})
# v610		((:)(:{hex4}{1}))
ip6 saddr ::1234;ok
# v611		((({hex4}:){1})(:))
ip6 saddr 1234::;ok
# v61		({v610}|{v611})
# v60		(::)
ip6 saddr ::/64;ok

- ip6 daddr != {::1234:1234:1234:1234:1234:1234:1234, 1234:1234::1234:1234:1234:1234:1234 };ok
ip6 daddr != ::1234:1234:1234:1234:1234:1234:1234-1234:1234::1234:1234:1234:1234:1234;ok
