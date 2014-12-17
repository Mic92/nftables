if INSTALL_SYSTEMD
systemd_unit_DATA = nftables.service

install-data-hook:
	${SED} -i 's|@sbindir[@]|${sbindir}/|g;s|@sysconfdir[@]|${sysconfdir}/|g' \
		${DESTDIR}${systemd_unitdir}/nftables.service
endif
