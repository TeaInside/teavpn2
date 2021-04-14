#
# SPDX-License-Identifier: GPL-2.0
#
# @author Ammar Faizi <ammarfaizi2@gmail.com> https://www.facebook.com/ammarfaizi2
# @license GNU GPL-2.0
#
# Makefile for BlueTea unit test on C framework
#
# Copyright (C) 2021  Ammar Faizi
#

DEP_DIRS += $(BASE_DEP_DIR)/src/bluetea/tests

TEST_EXEC_TMP :=
FBT_TEST_OBJ  :=
FBT_TEST_OBJ_TMP :=
FBT_TEST_EXEC :=
TEST_LIB_LDFLAGS := \
	-L$(BASE_DIR) -lteatest -Wl,-rpath=$(BASE_DIR) \
	-L$(BASE_DIR) -lbluetea -Wl,-rpath=$(BASE_DIR)

include $(BASE_DIR)/src/bluetea/tests/001_string/Makefile
include $(BASE_DIR)/src/bluetea/tests/002_tstack/Makefile
include $(BASE_DIR)/src/bluetea/tests/003_que/Makefile


bluetea_test: $(FBT_TEST_EXEC)


bluetea_test_clean:
	$(Q)$(RM) -vf $(FBT_TEST_OBJ)


.PHONY: bluetea_test bluetea_test_clean
