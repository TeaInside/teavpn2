#
# SPDX-License-Identifier: GPL-2.0
#
# @author Ammar Faizi <ammarfaizi2@gmail.com> https://www.facebook.com/ammarfaizi2
# @license GNU GPL-2.0
# @link https://github.com/ammarfaizi2/bluetea
#
# Makefile for BlueTea C framework
#
# Copyright (C) 2021  Ammar Faizi
#

DEP_DIRS += $(BASE_DEP_DIR)/src/bluetea
INCLUDE_DIR += -I$(BASE_DIR)/src/bluetea/include

#######################################
# Force this to be a simple variable
BLUETEA_CC_OBJ :=
BLUETEST_UNIT_TEST_OBJ :=
BLUETEST_UNIT_TEST_LIST :=
#######################################

BLUETEST_SHARED_OBJ = $(BASE_DIR)/libbluetest.so

include $(BASE_DIR)/src/bluetea/lib/Makefile
include $(BASE_DIR)/src/bluetea/bluetest/Makefile

#
# Include unit test
#
include $(BASE_DIR)/src/bluetea/tests/Makefile


bluetea: $(BLUETEA_CC_OBJ)

#
# Add more dependency chain to objects.
#
$(BLUETEA_CC_OBJ): | $(DEP_DIRS)


#
# Compile all $(BLUETEA_CC_OBJ)
#
$(BLUETEA_CC_OBJ):
	$(CC_PRINT)
	$(Q)$(CC) $(PIE_FLAGS) $(DEPFLAGS) $(CFLAGS) -c $(O_TO_C) -o $(@)


#
# Include generated dependencies
#
-include $(BLUETEA_CC_OBJ:$(BASE_DIR)/%.o=$(BASE_DEP_DIR)/%.d)


bluetea_clean: bluetest_clean
	$(Q)$(RM) -vrf $(BLUETEA_CC_OBJ) $(BLUETEST_UNIT_TEST_OBJ) $(BLUETEST_UNIT_TEST_LIST)


bluetea_test: $(BLUETEST_UNIT_TEST_LIST)


.PHONY: bluetea bluetea_test bluetest_clean
