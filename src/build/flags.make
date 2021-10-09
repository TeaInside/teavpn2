#
# SPDX-License-Identifier: GPL-2.0-only
#
# @author Ammar Faizi <ammarfaizi2@gmail.com> https://www.facebook.com/ammarfaizi2
# @license GNU GPL-2.0-only
#
# Flag for compilers and linkers.
#


#
# Are warnings allowed?
#
ifeq ($(BAN_WARN),1)
	override C_CXX_FLAGS += -Werror
endif

#
# Release or debug?
#
ifeq ($(DEBUG_MODE),1)
	override LDFLAGS	+= $(DEBUG_OPTIMIZATION_FLAG)
	override C_CXX_FLAGS	+= $(DEBUG_OPTIMIZATION_FLAG) $(C_CXX_FLAGS_DEBUG)
	#
	# Always sanitize debug build, unless otherwise specified.
	#
	ifndef SANITIZE
		SANITIZE := 1
	endif
else
	override LDFLAGS	+= $(OPTIMIZATION_FLAG) -DNDEBUG
	override C_CXX_FLAGS	+= $(OPTIMIZATION_FLAG) -DNDEBUG
endif


#
# Use sanitizer?
#
ifeq ($(SANITIZE),1)
	override C_CXX_FLAGS += \
		-fsanitize=undefined \
		-fno-sanitize-recover=undefined \
		-fsanitize=address

	override LIB_LDFLAGS := -lasan -lubsan $(LIB_LDFLAGS)
else
	SANITIZE := 0
endif


#
# File dependency generator (especially for headers)
#
DEPFLAGS = -MT "$@" -MMD -MP -MF "$(@:$(BASE_DIR)/%.o=$(BASE_DEP_DIR)/%.d)"

# Convert *.o filename to *.c
O_TO_C = $(@:$(BASE_DIR)/%.o=%.c)

override CFLAGS = $(C_CXX_FLAGS)
override CXXFLAGS = $(C_CXX_FLAGS) 

#
# Prepare warn flags for Clang or GCC.
#
ifeq ($(CC_TYPE),__clang)
	override CFLAGS += $(CLANG_WARN_FLAGS)
	override CXXFLAGS += $(CLANG_WARN_FLAGS)
else
	override CFLAGS += $(GCC_WARN_FLAGS)
	override CXXFLAGS += $(GCC_WARN_FLAGS)
endif

override CFLAGS += $(INCLUDE_DIR) $(USER_CFLAGS)
override CXXFLAGS += $(INCLUDE_DIR) $(USER_CXXFLAGS)
