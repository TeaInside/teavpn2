#
# SPDX-License-Identifier: GPL-2.0
#
# @author Ammar Faizi <ammarfaizi2@gmail.com> https://www.facebook.com/ammarfaizi2
# @license GNU GPL-v2
#
# TeaVPN2 - Fast and Free VPN Software
#


INCLUDE_DIR	+= -I$(BASE_DIR)/src/teavpn2/include
DEP_DIRS	+= $(BASE_DEP_DIR)/src/teavpn2


include $(BASE_DIR)/src/teavpn2/net/Makefile
include $(BASE_DIR)/src/teavpn2/lib/Makefile
include $(BASE_DIR)/src/teavpn2/server/Makefile
include $(BASE_DIR)/src/teavpn2/client/Makefile


OBJ_TMP_CC	:= \
	$(BASE_DIR)/src/teavpn2/cpu.o \
	$(BASE_DIR)/src/teavpn2/license.o \
	$(BASE_DIR)/src/teavpn2/print.o


#
# Don't compile main function if we have test
#
ifneq ($(DO_TEST),1)
	OBJ_TMP_CC += $(BASE_DIR)/src/teavpn2/main.o
endif


OBJ_PRE_CC	+= $(OBJ_TMP_CC)


$(OBJ_TMP_CC):
	$(S)echo "   CC		" "$(@:$(BASE_DIR)/%=%)"
	$(Q)$(CC) $(DEPFLAGS) $(CFLAGS) -c $(@:.o=.c) -o $(@)
