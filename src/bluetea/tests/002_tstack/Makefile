#
# SPDX-License-Identifier: GPL-2.0
#
# @author Ammar Faizi <ammarfaizi2@gmail.com> https://www.facebook.com/ammarfaizi2
# @license GNU GPL-2.0
#
# Makefile for stack test (002_tstack)
#
# Copyright (C) 2021  Ammar Faizi
#


DEP_DIRS += $(BASE_DEP_DIR)/src/bluetea/tests/002_tstack
FBT_TEST_EXEC += 002_tstack__exec_test
FBT_TEST_OBJ_TMP :=  \
	$(BASE_DIR)/src/bluetea/tests/002_tstack/002_tstack.o

TEST_EXEC_TMP := $(BASE_DIR)/src/bluetea/tests/002_tstack/002_tstack.test
FBT_TEST_OBJ += $(FBT_TEST_OBJ_TMP) $(TEST_EXEC_TMP)


$(FBT_TEST_OBJ_TMP): $(DEP_DIRS)

$(FBT_TEST_OBJ_TMP):
	$(CC_PRINT)
	$(Q)$(CC) $(PIE_FLAGS) $(DEPFLAGS) $(CFLAGS) -c $(O_TO_C) -o $(@)

-include $(FBT_TEST_OBJ_TMP:$(BASE_DIR)/%.o=$(BASE_DEP_DIR)/%.d)


$(TEST_EXEC_TMP): libteatest.so libbluetea.so


$(TEST_EXEC_TMP): $(FBT_TEST_OBJ_TMP)
	$(LD_PRINT)
	$(Q)$(LD) $(PIE_FLAGS) $(LDFLAGS) $(^) -o "$(@)" $(LIB_LDFLAGS) $(TEST_LIB_LDFLAGS)

002_tstack__exec_test: $(TEST_EXEC_TMP)
	$(<) $(shell which $(VG)) $(VGFLAGS)

.PHONY: 002_tstack__exec_test
