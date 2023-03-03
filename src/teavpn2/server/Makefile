#
# SPDX-License-Identifier: GPL-2.0-only
#
# @author Ammar Faizi <ammarfaizi2@gmail.com> https://www.facebook.com/ammarfaizi2
# @license GPL-2.0-only
#
# Copyright (C) 2021  Ammar Faizi
#

DEP_DIRS += $(BASE_DEP_DIR)/src/teavpn2/server

ifeq ($(CONFIG_LINUX),y)
	include $(BASE_DIR)/src/teavpn2/server/linux/Makefile
endif

OBJ_CC += \
	$(BASE_DIR)/src/teavpn2/server/entry.o
