#
# SPDX-License-Identifier: GPL-2.0
#
# @author Ammar Faizi <ammarfaizi2@gmail.com> https://www.facebook.com/ammarfaizi2
# @license GNU GPL-v2
#
# TeaVPN2 - Fast and Free VPN Software
#

VERSION	= 0
PATCHLEVEL = 0
SUBLEVEL = 1
EXTRAVERSION = -rc1
NAME = Fresh Water
PACKAGE_NAME = teavpn2-$(VERSION).$(PATCHLEVEL).$(SUBLEVEL)$(EXTRAVERSION)

CC 	:= cc
CXX	:= c++
LD	:= $(CXX)
VG	:= valgrind

RM	:= rm
MKDIR	:= mkdir
STRIP	:= strip



BASE_DIR	:= $(dir $(realpath $(lastword $(MAKEFILE_LIST))))
BASE_DIR	:= $(strip $(patsubst %/, %, $(BASE_DIR)))
BASE_DEP_DIR	:= $(BASE_DIR)/.deps
MAKEFILE_FILE	:= $(lastword $(MAKEFILE_LIST))



TARGET_BIN	:= teavpn2
LICENSES_DIR	:= $(BASE_DIR)/LICENSES



USE_SERVER	:= 1
USE_CLIENT	:= 1



ifneq (,$(findstring __clang__,$(CC_BUILTIN_CONSTANTS)))
	# Clang
	WARN_FLAGS := \
		-Wall \
		-Wextra \
		-Weverything \
		-Wno-padded \
		-Wno-unused-macros \
		-Wno-covered-switch-default \
		-Wno-disabled-macro-expansion \
		-Wno-language-extension-token
else
	# Pure GCC
	WARN_FLAGS := \
		-Wall \
		-Wextra \
		-Wformat \
		-Wformat-security \
		-Wformat-signedness \
		-Wsequence-point \
		-Wstrict-aliasing=3 \
		-Wstack-usage=2097152 \
		-Wunsafe-loop-optimizations
endif



#
# File dependency generator (especially for headers)
#
DEPFLAGS = -MT "$@" -MMD -MP -MF "$(@:$(BASE_DIR)/%.o=$(BASE_DEP_DIR)/%.d)"



LIB_LDFLAGS	:= -lpthread -lssl -lcrypto
LDFLAGS		:= -fPIE -fpie
CFLAGS		:= -fPIE -fpie -ggdb3
CXXFLAGS	:= -fPIE -fpie -ggdb3 -std=c++2a
VGFLAGS		:= \
	--leak-check=full \
	--show-leak-kinds=all \
	--track-origins=yes \
	--track-fds=yes \
	--error-exitcode=99 \
	--exit-on-first-error=yes \
	-s



ifndef DEFAULT_OPTIMIZATION
	DEFAULT_OPTIMIZATION = -O0
endif



#
# `CCXXFLAGS` is a flag that applies to `CFLAGS` and `CXXFLAGS`
#
CCXXFLAGS := \
	$(WARN_FLAGS) \
	-fstrict-aliasing \
	-fstack-protector-strong \
	-fno-omit-frame-pointer \
	-pedantic-errors \
	-D_GNU_SOURCE \
	-DVERSION=$(VERSION) \
	-DPATCHLEVEL=$(PATCHLEVEL) \
	-DSUBLEVEL=$(SUBLEVEL) \
	-DEXTRAVERSION="\"$(EXTRAVERSION)\"" \
	-DNAME="\"$(NAME)\""



ifeq ($(RELEASE_MODE),1)
	LDFLAGS		+= $(LDFLAGS) -O3
	CCXXFLAGS	+= -O3 -DNDEBUG
else
	LDFLAGS		+= $(DEFAULT_OPTIMIZATION)
	CCXXFLAGS	+= \
		$(DEFAULT_OPTIMIZATION) \
		-grecord-gcc-switches \
		-DTEAVPN_DEBUG
endif




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
# Verbose option
#
# `make V=1` will show the full commands
#
ifndef V
	V := 0
endif

ifeq ($(V),0)
	Q := @
	S := @
else
	Q :=
	S := @\#
endif



#######################################
# Force these to be a simple variable
TESTS		:=
OBJ_CC		:=
OBJ_PRE_CC	:=
OBJ_TMP_CC	:=
CFLAGS_TMP	:=
SHARED_LIB	:=
#######################################



all: $(TARGET_BIN)



include $(BASE_DIR)/src/ext/Makefile
include $(BASE_DIR)/src/teavpn2/Makefile

CFLAGS		:= $(INCLUDE_DIR) $(CFLAGS) $(CCXXFLAGS)
CXXFLAGS	:= $(INCLUDE_DIR) $(CXXFLAGS) $(CCXXFLAGS)

include $(BASE_DIR)/tests/Makefile


$(TARGET_BIN): $(OBJ_CC) $(OBJ_PRE_CC)
	$(S)echo "   LD		" "$(@)"
	$(Q)$(LD) $(LDFLAGS) $(OBJ_CC) $(OBJ_PRE_CC) -o "$@" $(LIB_LDFLAGS)


#
# Create dependendy directory
#
$(DEP_DIRS):
	$(S)echo "   MKDIR	" "$(@:$(BASE_DIR)/%=%)"
	$(Q)mkdir -p $(@)


#
# Compile object from main Makefile
#
$(OBJ_CC): $(MAKEFILE_FILE) | $(DEP_DIRS)
	$(S)echo "   CC		" "$(@:$(BASE_DIR)/%=%)"
	$(Q)$(CC) $(DEPFLAGS) $(CFLAGS) -c $(@:.o=.c) -o $(@)


#
# Add more dependency chain to object that is not
# compiled from the main Makefile
#
$(OBJ_PRE_CC): $(MAKEFILE_FILE) | $(DEP_DIRS)


#
# Include dependency
#
-include $(OBJ_CC:$(BASE_DIR)/%.o=$(BASE_DEP_DIR)/%.d)
-include $(OBJ_PRE_CC:$(BASE_DIR)/%.o=$(BASE_DEP_DIR)/%.d)



clean: clean_test
	$(Q)rm -rfv $(DEP_DIRS) $(OBJ_CC) $(OBJ_PRE_CC) $(TARGET_BIN)


clean_all: clean clean_test



.PHONY: all clean clean_all
