#
# SPDX-License-Identifier: GPL-2.0
#
# @author Ammar Faizi <ammarfaizi2@gmail.com> https://www.facebook.com/ammarfaizi2
# @license GNU GPL-2.0
#
# Copyright (C) 2021  Ammar Faizi
#

INCLUDE_DIR += -I$(BASE_DIR)/src/teavpn2/include
DEP_DIRS += $(BASE_DEP_DIR)/src/teavpn2/net


ifeq ($(UNAME_S),Linux)
	include $(BASE_DIR)/src/teavpn2/net/linux/Makefile
endif
