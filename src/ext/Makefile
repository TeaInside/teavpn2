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

	override LIB_LDFLAGS += -ldl
	OBJ_CC += $(BASE_DIR)/src/ext/hpc_emerg/src/emerg/arch/x64/emerg.o
	DEP_DIRS += $(BASE_DEP_DIR)/src/ext/hpc_emerg/src/emerg/arch/x64
endif

ifeq ($(CONFIG_IO_URING),y)
	override LIB_LDFLAGS += $(BASE_DIR)/src/ext/liburing/src/liburing.a
	EXT_DEP_FILE += $(BASE_DIR)/src/ext/liburing/src/liburing.a
endif

$(BASE_DIR)/src/ext/liburing/src/liburing.a:
	$(Q)echo "Building liburing ...";
	+$(Q)cd $(BASE_DIR)/src/ext/liburing && \
	./configure --cc="$(CC)" --cxx="$(CXX)";
	+$(Q)$(MAKE) CFLAGS="$(USER_CFLAGS)" -s --no-print-directory \
	-C $(BASE_DIR)/src/ext/liburing/src;
	$(Q)echo "---------------------------------------------------------------";

liburing_clean:
	+$(Q)$(MAKE) --no-print-directory -C $(BASE_DIR)/src/ext/liburing clean;

hpc_emerg_clean:
	+$(Q)$(MAKE) --no-print-directory -C $(BASE_DIR)/src/ext/hpc_emerg clean;

clean_all: liburing_clean hpc_emerg_clean

.PHONY: liburing_clean hpc_emerg_clean
