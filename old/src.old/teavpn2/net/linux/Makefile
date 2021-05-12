#
# SPDX-License-Identifier: GPL-2.0
#
# @author Ammar Faizi <ammarfaizi2@gmail.com> https://www.facebook.com/ammarfaizi2
# @license GNU GPL-v2
#
# TeaVPN2 - Fast and Free VPN Software
#


DEP_DIRS	+= $(BASE_DEP_DIR)/src/teavpn2/net/linux



OBJ_TMP_CC	:= \
	$(BASE_DIR)/src/teavpn2/net/linux/iface.o


OBJ_PRE_CC	+= $(OBJ_TMP_CC)


$(OBJ_TMP_CC):
	$(S)echo "   CC		" "$(@:$(BASE_DIR)/%=%)"
	$(Q)$(CC) $(DEPFLAGS) $(CFLAGS) -c $(@:.o=.c) -o $(@)
