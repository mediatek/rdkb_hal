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
hardware_platform = i686-linux-gnu

lib_LTLIBRARIES = libhal_platform.la
libhal_platform_la_CPPFLAGS = -I$(top_srcdir)/./include $(CPPFLAGS)
libhal_platform_la_SOURCES = platform_hal.c
libhal_platform_la_LDFLAGS = 
