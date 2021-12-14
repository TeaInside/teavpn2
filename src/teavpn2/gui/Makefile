#
# SPDX-License-Identifier: GPL-2.0-only
#
# @author Alviro Iskandar Setiawan <alviro.iskandar@gmail.com>
# @license GPL-2.0-only
#
# Copyright (C) 2021  Alviro Iskandar Setiawan
#

DEP_DIRS += $(BASE_DEP_DIR)/src/teavpn2/gui

OBJ_TMP_CC := \
	$(BASE_DIR)/src/teavpn2/gui/entry.o \
	$(BASE_DIR)/src/teavpn2/gui/gui_header.o \
	$(BASE_DIR)/src/teavpn2/gui/gui_home.o \
	$(BASE_DIR)/src/teavpn2/gui/gui_utils.o \
	$(BASE_DIR)/src/teavpn2/gui/gui_window.o

OBJ_PRE_CC += $(OBJ_TMP_CC)

$(OBJ_TMP_CC):
	$(CC_PRINT)
	$(Q)$(CC) $(PIE_FLAGS) $(DEPFLAGS) $(CFLAGS) -c $(O_TO_C) -o $(@)
