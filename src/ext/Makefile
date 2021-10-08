#
# SPDX-License-Identifier: GPL-2.0-only
#
# @author Ammar Faizi <ammarfaizi2@gmail.com> https://www.facebook.com/ammarfaizi2
# @license GPL-2.0-only
#
# Copyright (C) 2021  Ammar Faizi
#

INCLUDE_DIR += \
	-I$(BASE_DIR)/src/ext \
	-I$(BASE_DIR)/src/ext/hpc_emerg/src

include $(BASE_DIR)/src/ext/inih/Makefile


## Build HPC emerg objects
LIB_LDFLAGS += -ldl

ifeq ($(CONFIG_HPC_EMERGENCY),y)
# $(BASE_DIR)/src/ext/hpc_emerg/src/emerg/arch/x64/emerg.o:
# 	+$(Q)$(MAKE) \
# 	SANITIZE=$(SANITIZE) \
# 	-s --no-print-directory \
# 	-C $(BASE_DIR)/src/ext/hpc_emerg $(@)

OBJ_CC += $(BASE_DIR)/src/ext/hpc_emerg/src/emerg/arch/x64/emerg.o
DEP_DIRS += $(BASE_DEP_DIR)/src/ext/hpc_emerg/src/emerg/arch/x64
endif


hpc_emerg_clean:
	+$(Q)$(MAKE) \
	--no-print-directory \
	-C $(BASE_DIR)/src/ext/hpc_emerg clean

clean: hpc_emerg_clean

.PHONY: hpc_emerg_clean
