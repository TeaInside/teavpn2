#
# SPDX-License-Identifier: GPL-2.0
#
# @author Ammar Faizi <ammarfaizi2@gmail.com> https://www.facebook.com/ammarfaizi2
# @license GNU GPL-v2
#
# TeaVPN2 - Fast and Free VPN Software
#

DEP_DIRS	+= $(BASE_DEP_DIR)/tests/001_string
TEST_TVAR	:= $(BASE_DIR)/tests/001_string/001_string
TEST_EXEC	+= $(TEST_TVAR)__exec
TEST_TVAR_OBJ	:= $(BASE_DIR)/tests/001_string/001_string.o
TEST_OBJ	+= $(TEST_TVAR_OBJ)


$(TEST_TVAR_OBJ):
	$(S)echo "   CC		" "$(@:$(BASE_DIR)/%=%)"
	$(Q)$(CC) $(DEPFLAGS) $(CFLAGS) -c $(@:.o=.c) -o $(@)



$(TEST_TVAR).test: $(TEST_TVAR_OBJ) $(FWTEST_SO)
	$(S)echo "   LD		" "$(@)"
	$(Q)$(LD) $(LDFLAGS) -o "$@" $(^) $(LIB_LDFLAGS)



-include $(TEST_TVAR_OBJ:$(BASE_DIR)/%.o=$(BASE_DEP_DIR)/%.d)



$(TEST_TVAR)__exec: $(TEST_TVAR).test
	$(<) $(shell which $(VG)) $(VGFLAGS)



.PHONY: $(TEST_TVAR)
