#
# SPDX-License-Identifier: GPL-2.0
#
# @author Ammar Faizi <ammarfaizi2@gmail.com> https://www.facebook.com/ammarfaizi2
# @license GNU GPL-2.0
#
# Makefile for TeaTest on BlueTea C framework
#
# Copyright (C) 2021  Ammar Faizi
#

DEP_DIRS += $(BASE_DEP_DIR)/src/bluetea/teatest
TEA_TEST_OBJ_CC := \
	$(BASE_DIR)/src/bluetea/teatest/teatest.o


bluetea_teatest: libteatest.so

#
# Add more dependency chain to objects.
#
$(TEA_TEST_OBJ_CC): | $(DEP_DIRS)


#
# Compile all TeaTest objects.
#
$(TEA_TEST_OBJ_CC):
	$(CC_PRINT)
	$(Q)$(CC) $(PIC_FLAGS) $(DEPFLAGS) \
	$(filter-out -Wstack-usage=$(STACK_USAGE_SIZE), $(CFLAGS)) \
		-Wno-missing-noreturn \
		-Wno-alloca \
		-Wno-vla \
		-c $(O_TO_C) -o $(@)


#
# Include generated dependencies
#
-include $(TEA_TEST_OBJ_CC:$(BASE_DIR)/%.o=$(BASE_DEP_DIR)/%.d)


libteatest.so: libbluetea.so

#
# Link TeaTest shared object.
#
libteatest.so: $(TEA_TEST_OBJ_CC)
	$(LD_PRINT)
	$(Q)$(LD) $(PIC_FLAGS) $(LDFLAGS) $(^) -o "$(@)" $(LIB_LDFLAGS) -shared \
	-L$(BASE_DIR) -lbluetea -Wl,-rpath=$(BASE_DIR)


#
# Clean all BlueTea framework objects.
#
bluetea_teatest_clean:
	$(Q)$(RM) -vf libteatest.so $(TEA_TEST_OBJ_CC)


.PHONY: bluetea_teatest bluetea_teatest_clean
