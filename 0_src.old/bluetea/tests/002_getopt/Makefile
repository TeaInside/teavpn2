#
# SPDX-License-Identifier: GPL-2.0
#
# @author Ammar Faizi <ammarfaizi2@gmail.com> https://www.facebook.com/ammarfaizi2
# @license GNU GPL-2.0
# @link https://github.com/ammarfaizi2/bluetea
#
# Copyright (C) 2021  Ammar Faizi
#

DEP_DIRS += $(BASE_DEP_DIR)/src/bluetea/tests/002_getopt
THIS_TEST_NAME := $(BASE_DIR)/src/bluetea/tests/002_getopt/002_getopt
THIS_TEST_BIN := $(THIS_TEST_NAME).test
THIS_TEST_OBJ := $(THIS_TEST_NAME).o
THIS_TEST_EXTRA := $(BASE_DIR)/src/bluetea/lib/getopt.o

# Report to parent Makefile for running and cleaning.
BLUETEST_UNIT_TEST_OBJ += $(THIS_TEST_OBJ) $(THIS_TEST_BIN)
BLUETEST_UNIT_TEST_LIST += $(THIS_TEST_NAME)_do_test

$(THIS_TEST_OBJ): | $(DEP_DIRS)

$(THIS_TEST_OBJ):
	$(CC_PRINT)
	$(Q)$(CC) $(PIC_FLAGS) $(DEPFLAGS) $(CFLAGS) -c $(O_TO_C) -o $(@)

$(THIS_TEST_BIN): $(THIS_TEST_OBJ) $(BLUETEST_SHARED_OBJ) $(THIS_TEST_EXTRA)
	$(LD_PRINT)
	$(Q)$(CC) $(PIC_FLAGS) $(DEPFLAGS) $(CFLAGS) $(^) -o $(@) $(LIB_LDFLAGS)

$(THIS_TEST_NAME)_do_test: $(THIS_TEST_BIN)
	LD_LIBRARY_PATH=$(dir $(BLUETEST_SHARED_OBJ)) $(<) do_test $(shell which $(VG)) $(VGFLAGS)

-include $(THIS_TEST_OBJ:$(BASE_DIR)/%.o=$(BASE_DEP_DIR)/%.d)

.PHONY: $(THIS_TEST_NAME)_do_test
