
pkgsysconfdir = ${sysconfdir}/nftables
dist_pkgsysconf_DATA =	bridge-filter	\
			inet-filter	\
			ipv4-filter	\
			ipv4-mangle	\
			ipv4-nat	\
			ipv6-filter	\
			ipv6-mangle	\
			ipv6-nat

install-data-hook:
	${SED} -i 's|@sbindir[@]|${sbindir}/|g' ${DESTDIR}${pkgsysconfdir}/*
