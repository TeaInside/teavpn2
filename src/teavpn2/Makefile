#
# SPDX-License-Identifier: GPL-2.0
#
# @author Ammar Faizi <ammarfaizi2@gmail.com> https://www.facebook.com/ammarfaizi2
# @license GNU GPL-2.0
#
# Copyright (C) 2021  Ammar Faizi
#

INCLUDE_DIR += -I$(BASE_DIR)/src/teavpn2/include
DEP_DIRS += $(BASE_DEP_DIR)/src/teavpn2

BLUETEA_OBJ_EXTRA := \
	$(BASE_DIR)/src/bluetea/lib/arena.o \
	$(BASE_DIR)/src/bluetea/lib/getopt.o \
	$(BASE_DIR)/src/bluetea/lib/string.o \
	$(BASE_DIR)/src/bluetea/lib/string/strtrim.o


include $(BASE_DIR)/src/teavpn2/net/Makefile
# include $(BASE_DIR)/src/teavpn2/client/Makefile
include $(BASE_DIR)/src/teavpn2/server/Makefile


OBJ_TMP_CC := \
	$(BASE_DIR)/src/teavpn2/allocator.o \
	$(BASE_DIR)/src/teavpn2/main.o \
	$(BASE_DIR)/src/teavpn2/print.o


OBJ_PRE_CC += $(OBJ_TMP_CC) $(BLUETEA_OBJ_EXTRA)


$(OBJ_TMP_CC):
	$(CC_PRINT)
	$(Q)$(CC) $(PIE_FLAGS) $(DEPFLAGS) $(CFLAGS) -c $(O_TO_C) -o $(@)
