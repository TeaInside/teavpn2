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

OBJ_TMP_CC := \
	$(BASE_DIR)/src/teavpn2/allocator.o \
	$(BASE_DIR)/src/teavpn2/auth.o \
	$(BASE_DIR)/src/teavpn2/main.o \
	$(BASE_DIR)/src/teavpn2/print.o

OBJ_PRE_CC += $(OBJ_TMP_CC)

$(OBJ_TMP_CC):
	$(CC_PRINT)
	$(Q)$(CC) $(PIE_FLAGS) $(DEPFLAGS) $(CFLAGS) -c $(O_TO_C) -o $(@)
