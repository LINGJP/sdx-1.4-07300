etcdir = ${sysconfdir}
#dist_etc_DATA = cld-hostapd-wlan0.sh

misc_ddir = ${sysconfdir}/misc/wifi
dist_misc_d_DATA = hostapd.conf
dist_misc_d_DATA += hostapd.deny
dist_misc_d_DATA += hostapd.accept
dist_misc_d_DATA += wpa_supplicant.conf
dist_misc_d_DATA += p2p_supplicant.conf

init_ddir = ${sysconfdir}/init.d
dist_init_d_SCRIPTS = wlan

firmware_ddir = /lib/firmware/wlan/qca_cld
dist_firmware_d_DATA = WCNSS_qcom_cfg.ini

# Copy WCNSS_cfg.sdio.in to ../firmware/wlan/qca_cld/qca6174/
firmware_qca6174dir = /lib/firmware/wlan/qca_cld/qca6174
dist_firmware_qca6174_DATA = WCNSS_cfg.sdio.ini

# Rename WCNSS_cfg.sdio.ini to WCNSS_qcom_cfg.ini
install-data-hook:$(DESTDIR)$(firmware_qca6174dir)/WCNSS_cfg.sdio.ini
	cd $(DESTDIR)$(firmware_qca6174dir) && \
		mv -f WCNSS_cfg.sdio.ini WCNSS_qcom_cfg.ini

