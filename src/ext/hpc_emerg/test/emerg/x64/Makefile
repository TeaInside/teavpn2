# SPDX-License-Identifier: GPL-2.0-only
#
# @author Ammar Faizi <ammarfaizi2@gmail.com> https://www.facebook.com/ammarfaizi2
# @license GPL-2.0-only
#
# Copyright (C) 2021  Ammar Faizi
#

DEP_DIRS += $(BASE_DEP_DIR)/test/emerg/x64

TEST_EXE := \
	$(BASE_DIR)/test/emerg/x64/bug_on \
	$(BASE_DIR)/test/emerg/x64/warn_on

$(TEST_EXE): $(TARGET_BIN)
	$(CC_PRINT)
	$(Q)$(CC) $(PIC_FLAGS) $(DEPFLAGS_EXE) $(CFLAGS) $(EXE_TO_C) -o $(@) -L$(BASE_DIR) -lhpcemerg -lpthread

#
# Include generated dependencies
#
-include $(TEST_EXE:$(BASE_DIR)/%=$(BASE_DEP_DIR)/%.d)

test_x64: $(TEST_EXE)
	$(Q)for i in $(TEST_EXE); do \
		echo "Running test $$i"; \
		LD_LIBRARY_PATH="$(LD_LIBRARY_PATH):$(LD_LIBRARY_PATH)" $$i || exit $$?; \
	done;


.PHONY: test_x64
