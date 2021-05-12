#
# SPDX-License-Identifier: GPL-2.0
#
# @author Ammar Faizi <ammarfaizi2@gmail.com> https://www.facebook.com/ammarfaizi2
# @license GNU GPL-2.0
#
# Copyright (C) 2021  Ammar Faizi
#

DEP_DIRS += $(BASE_DEP_DIR)/src/teavpn2/server


ifeq ($(UNAME_S),Linux)
	include $(BASE_DIR)/src/teavpn2/server/linux/Makefile
endif


OBJ_TMP_CC := \
	$(BASE_DIR)/src/teavpn2/server/argv.o \
	$(BASE_DIR)/src/teavpn2/server/entry.o

OBJ_PRE_CC += $(OBJ_TMP_CC)


$(OBJ_TMP_CC):
	$(CC_PRINT)
	$(Q)$(CC) $(PIC_FLAGS) $(DEPFLAGS) $(CFLAGS) -c $(O_TO_C) -o $(@)
