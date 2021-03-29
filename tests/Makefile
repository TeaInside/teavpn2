#
# SPDX-License-Identifier: GPL-2.0
#
# @author Ammar Faizi <ammarfaizi2@gmail.com> https://www.facebook.com/ammarfaizi2
# @license GNU GPL-v2
#
# TeaVPN2 - Fast and Free VPN Software
#


INCLUDE_DIR	+= -I$(BASE_DIR)/tests
DEP_DIRS	+= $(BASE_DEP_DIR)/src/teavpn2/tests




###################################################################
#
# Build Tea Test (Unit Test Framework for C project)
#
###################################################################
FWTEST_SO	:= $(BASE_DIR)/tests/libteatest.so
FWTEST_OBJ	:= $(BASE_DIR)/tests/teatest.o



$(FWTEST_OBJ):
	$(S)echo "   CC		" "$(@:$(BASE_DIR)/%=%)"
	$(Q)$(CC) $(DEPFLAGS) $(CFLAGS) -Wno-missing-noreturn -c $(@:.o=.c) -o $(@)



$(FWTEST_SO): $(FWTEST_OBJ) $(OBJ_CC) $(OBJ_PRE_CC)
	$(S)echo "   LD		" "$(@)"
	$(Q)$(LD) $(LDFLAGS) $(^) -shared -o "$@" $(LIB_LDFLAGS)



-include $(FWTEST_OBJ:$(BASE_DIR)/%.o=$(BASE_DEP_DIR)/%.d)
##################################################################


include $(BASE_DIR)/tests/001_string/Makefile


test: $(FWTEST_SO) $(TEST_EXEC)



clean_test:
	$(Q)rm -vf $(FWTEST_OBJ) $(TEST_EXEC) $(TEST_OBJ)



.PHONY: test clean_test
