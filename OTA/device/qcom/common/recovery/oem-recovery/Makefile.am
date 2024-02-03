# Makefile.am
ACLOCAL_AMFLAGS := -I m4

AM_CFLAGS := -Wundef \
             -Wstrict-prototypes \
             -Wno-trigraphs \
             -g -O0 \
             -fno-inline \
             -fno-short-enums \
             -fpic

AM_CPPFLAGS := \
              -I. \
              -I$(WORKSPACE)/system/core/include \
              -I$(WORKSPACE)/OTA/recovery \
              -I$(WORKSPACE)/system/core/libsparse \
              -Dstrlcpy=g_strlcpy \
              -Dstrlcat=g_strlcat

oem_recovery_sources := gpt-utils.cpp dec.cpp oem-updater.cpp recovery-ufs-bsg.cpp

library_includedir := $(pkgincludedir)

lib_LTLIBRARIES := librecovery_updater_msm.la
librecovery_updater_msm_la_SOURCES := $(oem_recovery_sources)

librecovery_updater_msm_la_CFLAGS := $(AM_CFLAGS) @LIBION_CFLAGS@
librecovery_updater_msm_la_CPPFLAGS := $(AM_CPPFLAGS) @LIBION_CFLAGS@
librecovery_updater_msm_la_LIBADD := -lm -lpthread -lsparse
librecovery_updater_msm_la_LDFLAGS := -all-static

if USE_GLIB
librecovery_updater_msm_la_CFLAGS += -DUSE_GLIB @GLIB_CFLAGS@
librecovery_updater_msm_la_CPPFLAGS += -DUSE_GLIB @GLIB_CFLAGS@
librecovery_updater_msm_la_LIBADD +=  @GLIB_LIBS@
endif
