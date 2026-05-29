##########################################################################
# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2023 MediaTek Inc.
#
##########################################################################
AM_CFLAGS = -D_ANSC_LINUX
AM_CFLAGS += -D_ANSC_USER
AM_CFLAGS += -D_ANSC_LITTLE_ENDIAN_

AM_CPPFLAGS = -Wall -Werror
ACLOCAL_AMFLAGS = -I m4
hardware_platform = armv7ahf-neon-rdk-linux-musleabi

lib_LTLIBRARIES = libhal_wifi.la
libhal_wifi_la_CPPFLAGS = -I$(top_srcdir)/include $(CPPFLAGS)
libhal_wifi_la_SOURCES = wifi_hal.c client_wifi_hal.c
libhal_wifi_la_LDFLAGS = -lev -lwpa_client

#wifihal test binary
bin_PROGRAMS = wifihal
wifihal_CPPFLAGS = -I$(top_srcdir)/include $(CPPFLAGS) -D_WIFI_HAL_TEST_
wifihal_SOURCES = wifi_hal.c client_wifi_hal.c
