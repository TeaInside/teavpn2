#
# SPDX-License-Identifier: GPL-2.0-only
#
# @author Ammar Faizi <ammarfaizi2@gmail.com> https://www.facebook.com/ammarfaizi2
# @license GPL-2.0-only
#
# TeaVPN2 - Free VPN Software
#
# Copyright (C) 2021  Ammar Faizi
#

VERSION	= 0
PATCHLEVEL = 1
SUBLEVEL = 2
EXTRAVERSION := -rc1
NAME = Green Grass
TARGET_BIN = teavpn2

ifneq ($(MAKECMDGOALS),clean)
ifneq ($(MAKECMDGOALS),clean_all)
	include config-host.mak
endif
endif

override USER_CFLAGS := $(CFLAGS)
override USER_CXXFLAGS := $(CXXFLAGS)
override USER_LDFLAGS := $(LDFLAGS)
override USER_LIB_LDFLAGS := $(LIB_LDFLAGS)

MKDIR		:= mkdir
BASE_DIR	:= $(dir $(realpath $(lastword $(MAKEFILE_LIST))))
BASE_DIR	:= $(strip $(patsubst %/, %, $(BASE_DIR)))
BASE_DEP_DIR	:= $(BASE_DIR)/.deps
MAKEFILE_FILE	:= $(lastword $(MAKEFILE_LIST))
INCLUDE_DIR	= -I$(BASE_DIR)
PACKAGE_NAME	:= $(TARGET_BIN)-$(VERSION).$(PATCHLEVEL).$(SUBLEVEL)$(EXTRAVERSION)

ifndef DEBUG_MODE
	DEBUG_MODE := 0
endif

ifndef OPTIMIZATION_FLAG
	OPTIMIZATION_FLAG := -O2
endif


# This will be appended to {C,CXX,LD}FLAGS only when DEBUG_MODE is 1.
DEBUG_OPTIMIZATION_FLAG	:= -O0


STACK_USAGE_WARN	:= 8192
override PIE_FLAGS	:= -fpie -fPIE
override LDFLAGS	:= -ggdb3 -rdynamic $(LDFLAGS)
override LIB_LDFLAGS	:= -lpthread $(LIB_LDFLAGS)
override C_CXX_FLAGS	:= \
	-ggdb3 \
	-fstrict-aliasing \
	-fno-stack-protector \
	-fdata-sections \
	-ffunction-sections \
	-D_GNU_SOURCE \
	-DVERSION=$(VERSION) \
	-DPATCHLEVEL=$(PATCHLEVEL) \
	-DSUBLEVEL=$(SUBLEVEL) \
	-DEXTRAVERSION="\"$(EXTRAVERSION)\"" \
	-DNAME="\"$(NAME)\"" \
	-include $(BASE_DIR)/config-host.h $(C_CXX_FLAGS)

ifeq ($(CONFIG_GUI),y)
override LIB_LDFLAGS += $(shell pkg-config --libs gtk+-3.0)
override C_CXX_FLAGS += $(shell pkg-config --cflags gtk+-3.0)
endif

override C_CXX_FLAGS_DEBUG := $(C_CXX_FLAGS_DEBUG)

override GCC_WARN_FLAGS := \
	-Wall \
	-Wextra \
	-Wformat \
	-Wformat-security \
	-Wformat-signedness \
	-Wsequence-point \
	-Wstrict-aliasing=3 \
	-Wstack-usage=$(STACK_USAGE_WARN) \
	-Wunsafe-loop-optimizations $(GCC_WARN_FLAGS)

override CLANG_WARN_FLAGS := \
	-Wall \
	-Wextra \
	$(CLANG_WARN_FLAGS)

include $(BASE_DIR)/src/build/flags.make
include $(BASE_DIR)/src/build/print.make

#
# These empty assignments force the variables to be a simple variable.
#
OBJ_CC		:=

#
# OBJ_PRE_CC is a collection of object files which the compile rules are
# defined in sub Makefile.
#
OBJ_PRE_CC	:=


#
# OBJ_TMP_CC is a temporary variable which is used in the sub Makefile.
#
OBJ_TMP_CC	:=

#
# Extension dependency file, not always supposed to be compiled.
#
EXT_DEP_FILE	:= $(MAKEFILE_FILE) config-host.mak config-host.h


all: __all


config-host.mak: configure
	@if [ ! -e "$@" ]; then					\
	  echo "Running configure ...";				\
	  LDFLAGS="$(USER_LDFLAGS)"				\
	  LIB_LDFLAGS="$(USER_LIB_LDFLAGS)"			\
	  CFLAGS="$(USER_CFLAGS)" 				\
	  CXXFLAGS="$(USER_CXXFLAGS)"				\
	  ./configure;						\
	else							\
	  echo "$@ is out-of-date";				\
	  echo "Running configure ...";				\
	  LDFLAGS="$(USER_LDFLAGS)"				\
	  LIB_LDFLAGS="$(USER_LIB_LDFLAGS)"			\
	  CFLAGS="$(USER_CFLAGS)" 				\
	  CXXFLAGS="$(USER_CXXFLAGS)"				\
	  sed -n "/.*Configured with/s/[^:]*: //p" "$@" | sh;	\
	fi


include $(BASE_DIR)/src/Makefile


#
# Create dependency directories
#
$(DEP_DIRS):
	$(MKDIR_PRINT)
	$(Q)$(MKDIR) -p $(@)


#
# Add more dependency chain to objects that are not compiled from the main
# Makefile (the main Makefile is *this* Makefile).
#
$(OBJ_CC): $(EXT_DEP_FILE) | $(DEP_DIRS)
$(OBJ_PRE_CC): $(EXT_DEP_FILE) | $(DEP_DIRS)


#
# Compile object from the main Makefile (the main Makefile is *this* Makefile).
#
$(OBJ_CC):
	$(CC_PRINT)
	$(Q)$(CC) $(PIE_FLAGS) $(DEPFLAGS) $(CFLAGS) -c $(O_TO_C) -o $(@)


#
# Include generated dependencies
#
-include $(OBJ_CC:$(BASE_DIR)/%.o=$(BASE_DEP_DIR)/%.d)
-include $(OBJ_PRE_CC:$(BASE_DIR)/%.o=$(BASE_DEP_DIR)/%.d)


#
# Link the target bin.
#
$(TARGET_BIN): $(OBJ_CC) $(OBJ_PRE_CC)
	$(LD_PRINT)
	$(Q)$(LD) $(PIE_FLAGS) $(LDFLAGS) $(^) -o "$(@)" $(LIB_LDFLAGS)


__all: $(EXT_DEP_FILE) $(TARGET_BIN)


clean:
	$(Q)$(RM) -vf \
		$(TARGET_BIN) \
		$(OBJ_CC) \
		$(OBJ_PRE_CC) \
		config-host.mak \
		config-host.h \
		config.log;

clean_all: clean


.PHONY: __all all clean clean_all
