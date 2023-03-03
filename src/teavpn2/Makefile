#
# SPDX-License-Identifier: GPL-2.0-only
#
# @author Ammar Faizi <ammarfaizi2@gmail.com> https://www.facebook.com/ammarfaizi2
# @license GPL-2.0-only
#
# Copyright (C) 2021  Ammar Faizi
#

DEP_DIRS += $(BASE_DEP_DIR)/src/teavpn2

include $(BASE_DIR)/src/teavpn2/client/Makefile
include $(BASE_DIR)/src/teavpn2/server/Makefile
include $(BASE_DIR)/src/teavpn2/net/Makefile

ifeq ($(CONFIG_GUI),y)
include $(BASE_DIR)/src/teavpn2/gui/Makefile
endif

OBJ_CC += \
	$(BASE_DIR)/src/teavpn2/allocator.o \
	$(BASE_DIR)/src/teavpn2/auth.o \
	$(BASE_DIR)/src/teavpn2/main.o \
	$(BASE_DIR)/src/teavpn2/print.o
