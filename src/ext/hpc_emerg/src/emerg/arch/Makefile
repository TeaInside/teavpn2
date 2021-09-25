#
# SPDX-License-Identifier: GPL-2.0-only
#
# @author Ammar Faizi <ammarfaizi2@gmail.com> https://www.facebook.com/ammarfaizi2
# @license GPL-2.0-only
#
# Copyright (C) 2021  Ammar Faizi
#

DEP_DIRS += $(BASE_DEP_DIR)/src/emerg/arch


#
# OS and platform detection flags
#
ifeq ($(OS),Windows_NT)
	ifeq ($(PROCESSOR_ARCHITEW6432),AMD64)
		include $(BASE_DIR)/src/emerg/arch/x64/Makefile
	else
		ifeq ($(PROCESSOR_ARCHITECTURE),AMD64)
			include $(BASE_DIR)/src/emerg/arch/x64/Makefile
		endif
		ifeq ($(PROCESSOR_ARCHITECTURE),x86)
			# include $(BASE_DIR)/src/emerg/arch/x86/Makefile
		endif
	endif
else
	UNAME_S := $(shell uname -s)
	ifeq ($(UNAME_S),Linux)
		C_CXX_FLAGS += -DLINUX
	endif
	ifeq ($(UNAME_S),Darwin)
		C_CXX_FLAGS += -DOSX
	endif

	UNAME_P := $(shell uname -p)
	ifeq ($(UNAME_P),x86_64)
		include $(BASE_DIR)/src/emerg/arch/x64/Makefile
	endif
	ifneq ($(filter %86,$(UNAME_P)),)
		# include $(BASE_DIR)/src/emerg/arch/x86/Makefile
	endif
	ifneq ($(filter arm%,$(UNAME_P)),)
		# include $(BASE_DIR)/src/emerg/arch/arm/Makefile
	endif
endif
