#
# SPDX-License-Identifier: GPL-2.0
#
# @author Ammar Faizi <ammarfaizi2@gmail.com> https://www.facebook.com/ammarfaizi2
# @license GNU GPL-2.0
#
# TeaVPN2 - Free VPN Software
#
# Copyright (C) 2021  Ammar Faizi
#

VERSION	= 0
PATCHLEVEL = 1
SUBLEVEL = 2
EXTRAVERSION =
NAME = Black Mosquito
TARGET_BIN = teavpn2
PACKAGE_NAME = $(TARGET_BIN)-$(VERSION).$(PATCHLEVEL).$(SUBLEVEL)$(EXTRAVERSION)


#
# Bin
#
AS	:= as
CC 	:= cc
CXX	:= c++
LD	:= $(CXX)
VG	:= valgrind
RM	:= rm
MKDIR	:= mkdir
STRIP	:= strip
OBJCOPY	:= objcopy
OBJDUMP	:= objdump
READELF	:= readelf


LIB_LDFLAGS	:= -lpthread
LDFLAGS		:= -ggdb3
CFLAGS		:= -std=c11
CXXFLAGS	:= -std=c++2a
ifeq ($(FORCE_PIE),1)
	PIC_FLAGS := -fPIE -fpie
else
	PIC_FLAGS := -fPIC -fpic
endif
PIE_FLAGS := -fPIE -fpie


# `C_CXX_FLAGS` will be appended to `CFLAGS` and `CXXFLAGS`.
C_CXX_FLAGS := \
	-ggdb3 \
	-fstrict-aliasing \
	-fstack-protector-strong \
	-fno-omit-frame-pointer \
	-fdata-sections \
	-ffunction-sections \
	-pedantic-errors \
	-D_GNU_SOURCE \
	-DVERSION=$(VERSION) \
	-DPATCHLEVEL=$(PATCHLEVEL) \
	-DSUBLEVEL=$(SUBLEVEL) \
	-DEXTRAVERSION="\"$(EXTRAVERSION)\"" \
	-DNAME="\"$(NAME)\""


# Valgrind flags
VGFLAGS	:= \
	--leak-check=full \
	--show-leak-kinds=all \
	--track-origins=yes \
	--track-fds=yes \
	--error-exitcode=99 \
	-s

ifndef DEFAULT_OPTIMIZATION
	DEFAULT_OPTIMIZATION = -O0
endif

STACK_USAGE_SIZE := 2097152

GCC_WARN_FLAGS := \
	-Wall \
	-Wextra \
	-Wformat \
	-Wformat-security \
	-Wformat-signedness \
	-Wsequence-point \
	-Wstrict-aliasing=3 \
	-Wstack-usage=$(STACK_USAGE_SIZE) \
	-Wunsafe-loop-optimizations

CLANG_WARN_FLAGS := \
	-Wall \
	-Wextra \
	-Weverything \
	-Wno-padded \
	-Wno-unused-macros \
	-Wno-covered-switch-default \
	-Wno-disabled-macro-expansion \
	-Wno-language-extension-token \
	-Wno-used-but-marked-unused


BASE_DIR	:= $(dir $(realpath $(lastword $(MAKEFILE_LIST))))
BASE_DIR	:= $(strip $(patsubst %/, %, $(BASE_DIR)))
BASE_DEP_DIR	:= $(BASE_DIR)/.deps
MAKEFILE_FILE	:= $(lastword $(MAKEFILE_LIST))
INCLUDE_DIR	= -I$(BASE_DIR)


ifneq ($(words $(subst :, ,$(BASE_DIR))), 1)
$(error Source directory cannot contain spaces or colons)
endif


include $(BASE_DIR)/src/build/flags.make
include $(BASE_DIR)/src/build/print.make

#######################################
# Force these to be a simple variable
OBJ_CC		:=
OBJ_PRE_CC	:=
OBJ_TMP_CC	:=
SHARED_LIB	:=
#######################################

all: $(TARGET_BIN)

include $(BASE_DIR)/src/Makefile


#
# Create dependendy directory
#
$(DEP_DIRS):
	$(MKDIR_PRINT)
	$(Q)$(MKDIR) -p $(@)


#
# Add more dependency chain to objects that are not
# compiled from the main Makefile (main Makefile is this Makefile).
#
$(OBJ_CC): $(MAKEFILE_FILE) | $(DEP_DIRS)
$(OBJ_PRE_CC): $(MAKEFILE_FILE) | $(DEP_DIRS)


#
# Compile object from main Makefile (main Makefile is this Makefile).
#
$(OBJ_CC):
	$(CC_PRINT)
	$(Q)$(CC) $(PIC_FLAGS) $(DEPFLAGS) $(CFLAGS) -c $(O_TO_C) -o $(@)


#
# Include generated dependencies
#
-include $(OBJ_CC:$(BASE_DIR)/%.o=$(BASE_DEP_DIR)/%.d)
-include $(OBJ_PRE_CC:$(BASE_DIR)/%.o=$(BASE_DEP_DIR)/%.d)


#
# Link the target bin.
#
$(TARGET_BIN): $(OBJ_CC) $(OBJ_PRE_CC) $(FBT_CC_OBJ)
	$(LD_PRINT)
	$(Q)$(LD) $(PIC_FLAGS) $(LDFLAGS) $(^) -o "$(@)" $(LIB_LDFLAGS)


clean: bluetea_clean
	$(Q)$(RM) -vrf $(TARGET_BIN) $(DEP_DIRS) $(OBJ_CC) $(OBJ_PRE_CC)


.PHONY: all clean
