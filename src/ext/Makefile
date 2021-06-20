#
# SPDX-License-Identifier: GPL-2.0
#
# @author Ammar Faizi <ammarfaizi2@gmail.com> https://www.facebook.com/ammarfaizi2
# @license GNU GPL-2.0
#
# Copyright (C) 2021  Ammar Faizi
#

INCLUDE_DIR	+= -I$(BASE_DIR)/src/ext
DEP_DIRS	+= $(BASE_DEP_DIR)/src/teavpn2/ext

include $(BASE_DIR)/src/ext/inih/Makefile


INCLUDE_DIR	+= -I$(BASE_DIR)/src/ext/liburing/src/include
LIBURING_OBJ	+= \
	$(BASE_DIR)/src/ext/liburing/src/syscall.ol \
	$(BASE_DIR)/src/ext/liburing/src/setup.ol \
	$(BASE_DIR)/src/ext/liburing/src/register.ol \
	$(BASE_DIR)/src/ext/liburing/src/queue.ol

OBJ_EXTRA	+= $(LIBURING_OBJ)


export V

$(LIBURING_OBJ):
	+$(Q)cd $(BASE_DIR)/src/ext/liburing && ./configure && make;

liburing_clean:
	+$(Q)cd $(BASE_DIR)/src/ext/liburing && make clean;

ext_clean: liburing_clean

.PHONY: ext_clean liburing_clean
