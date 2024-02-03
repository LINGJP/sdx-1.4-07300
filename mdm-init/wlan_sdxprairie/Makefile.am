etcdir = ${sysconfdir}
dist_etc_DATA = cld-hostapd-wlan0.sh
dist_etc_DATA += cld-hostapd-wlan1.sh
dist_etc_DATA += cld-hostapd-wlan2.sh

misc_ddir = ${sysconfdir}/misc/wifi
dist_misc_d_DATA = hostapd.conf
dist_misc_d_DATA += hostapd-wlan1.conf
dist_misc_d_DATA += hostapd-wlan2.conf
dist_misc_d_DATA += sta_mode_hostapd.conf
dist_misc_d_DATA += wpa_supplicant.conf
dist_misc_d_DATA += WCNSS_qcom_cfg.ini

init_ddir = ${sysconfdir}/init.d
dist_init_d_SCRIPTS = wlan
dist_init_d_SCRIPTS += start_cnss_le

firmware_ddir = ${base_libdir}/firmware/wlan/qca_cld
dist_firmware_d_DATA = WCNSS_qcom_cfg.ini

install-data-hook:
	$(LN_S) -nf $(misc_ddir)/WCNSS_qcom_cfg.ini $(DESTDIR)$(firmware_ddir)/WCNSS_qcom_cfg.ini
	chown root:1001 $(DESTDIR)$(misc_ddir)/WCNSS_qcom_cfg.ini
	chmod 0664 $(DESTDIR)$(misc_ddir)/WCNSS_qcom_cfg.ini
