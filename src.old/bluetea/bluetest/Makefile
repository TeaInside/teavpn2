#
# SPDX-License-Identifier: GPL-2.0
#
# @author Ammar Faizi <ammarfaizi2@gmail.com> https://www.facebook.com/ammarfaizi2
# @license GNU GPL-2.0
# @link https://github.com/ammarfaizi2/bluetea
#
# Makefile for BlueTea C framework (bluetest)
#
# Copyright (C) 2021  Ammar Faizi
#

INCLUDE_DIR += -I$(BASE_DIR)/src/bluetea
DEP_DIRS += $(BASE_DEP_DIR)/src/bluetea/bluetest
BLUETEST_OBJ := $(BASE_DIR)/src/bluetea/bluetest/bluetest.o

#
# Add more dependency chain to objects.
#
$(BLUETEST_OBJ): | $(DEP_DIRS)


$(BLUETEST_OBJ):
	$(CC_PRINT)
	$(Q)$(CC) $(PIC_FLAGS) $(DEPFLAGS) $(CFLAGS) -c $(O_TO_C) -o $(@)


$(BLUETEST_SHARED_OBJ): $(BLUETEST_OBJ)
	$(LD_PRINT)
	$(Q)$(CC) $(PIC_FLAGS) $(DEPFLAGS) $(CFLAGS) -shared $(BLUETEST_OBJ) -o $(@) $(LIB_LDFLAGS)


#
# Include generated dependencies
#
-include $(BLUETEST_OBJ:$(BASE_DIR)/%.o=$(BASE_DEP_DIR)/%.d)


bluetest_clean:
	$(Q)$(RM) -vf $(BLUETEST_OBJ) $(BLUETEST_SHARED_OBJ)


.PHONY: bluetest_clean
