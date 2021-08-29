#
# SPDX-License-Identifier: GPL-2.0-only
#
# @author Ammar Faizi <ammarfaizi2@gmail.com> https://www.facebook.com/ammarfaizi2
# @license GNU GPL-2.0-only
#
# Flag for compilers and linkers.
#


#
# Make sure our compilers have `__GNUC__` support
#
CC_BUILTIN_CONSTANTS	:= $(shell $(CC) -dM -E - < /dev/null)
CXX_BUILTIN_CONSTANTS	:= $(shell $(CXX) -dM -E - < /dev/null)
ifeq (,$(findstring __GNUC__,$(CC_BUILTIN_CONSTANTS)))
	CC := /bin/echo I want __GNUC__! && false
endif

ifeq (,$(findstring __GNUC__,$(CXX_BUILTIN_CONSTANTS)))
	CXX := /bin/echo I want __GNUC__! && false
endif


#
# Prepare warn flags for Clang or GCC.
#
ifneq (,$(findstring __clang__,$(CC_BUILTIN_CONSTANTS)))
	# It's clang
	WARN_FLAGS := $(CLANG_WARN_FLAGS)
else
	# It's pure GCC
	WARN_FLAGS := $(GCC_WARN_FLAGS)
endif


#
# Are warnings allowed?
#
ifeq ($(BAN_WARN),1)
	WARN_FLAGS := -Werror $(WARN_FLAGS)
endif


C_CXX_FLAGS += $(WARN_FLAGS)


#
# Release or debug?
#
ifeq ($(RELEASE_MODE),1)
	LDFLAGS		+= -O3
	C_CXX_FLAGS	+= -O3 $(C_CXX_FLAGS_RELEASE)
else
	LDFLAGS		+= $(DEFAULT_OPTIMIZATION)
	C_CXX_FLAGS	+= $(DEFAULT_OPTIMIZATION) $(C_CXX_FLAGS_DEBUG)

	#
	# Always sanitize debug build, unless otherwise specified.
	#
	ifndef SANITIZE
		SANITIZE = 1
	endif
endif


#
# Use sanitizer?
#
ifeq ($(SANITIZE),1)
	C_CXX_FLAGS += \
		-fsanitize=undefined \
		-fno-sanitize-recover=undefined
	LIB_LDFLAGS += -lubsan
endif


#
# File dependency generator (especially for headers)
#
DEPFLAGS = -MT "$@" -MMD -MP -MF "$(@:$(BASE_DIR)/%.o=$(BASE_DEP_DIR)/%.d)"
DEPFLAGS_EXE = -MT "$@" -MMD -MP -MF "$(@:$(BASE_DIR)/%=$(BASE_DEP_DIR)/%.d)"


#
# OS and platform detection flags
#
ifeq ($(OS),Windows_NT)
	C_CXX_FLAGS += -DWIN32
	ifeq ($(PROCESSOR_ARCHITEW6432),AMD64)
		C_CXX_FLAGS += -DAMD64
	else
		ifeq ($(PROCESSOR_ARCHITECTURE),AMD64)
			C_CXX_FLAGS += -DAMD64
		endif
		ifeq ($(PROCESSOR_ARCHITECTURE),x86)
			C_CXX_FLAGS += -DIA32
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
		C_CXX_FLAGS += -DAMD64
	endif
	ifneq ($(filter %86,$(UNAME_P)),)
		C_CXX_FLAGS += -DIA32
	endif
	ifneq ($(filter arm%,$(UNAME_P)),)
		C_CXX_FLAGS += -DARM
	endif
endif


# Convert *.o filename to *.c
O_TO_C = $(@:$(BASE_DIR)/%.o=%.c)

EXE_TO_C = $(@:$(BASE_DIR)/%=%.c)

CFLAGS = $(C_CXX_FLAGS) $(INCLUDE_DIR)
CXXFLAGS = $(C_CXX_FLAGS) $(INCLUDE_DIR)
