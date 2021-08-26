# SPDX-License-Identifier: GPL-2.0-only
#
# @author Ammar Faizi <ammarfaizi2@gmail.com> https://www.facebook.com/ammarfaizi2
# @license GPL-2.0-only
#
# hpc_emerg - Emergency alert and tracer for realtime
# high-performance computing app (work in progress,
# currently supported env is only Linux x86-64).
#
# Copyright (C) 2021  Ammar Faizi
#

VERSION	= 0
PATCHLEVEL = 0
SUBLEVEL = 1
EXTRAVERSION := -rc1
NAME = libhpcemerg
TARGET_BIN = libhpcemerg.so

GIT_HASH = $(shell git log --pretty=format:'%H' -n 1 2>/dev/null || echo "")
EXTRAVERSION := $(EXTRAVERSION)-$(GIT_HASH)

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
HOSTCC	:= $(CC)
HOSTCXX	:= $(CXX)

# Flag to link any library to $(TARGET_BIN)
# (middle argumets)
LDFLAGS		:= -rdynamic -ggdb3

# Flag to link any library to $(TARGET_BIN)
# (end arguments)
LIB_LDFLAGS	:= -lpthread -ldl

# Flags that only apply to C
CFLAGS		:=

# Flags that only apply to C++
CXXFLAGS	:=

# Flags that only apply to PIC objects.
PIC_FLAGS	:= -fPIC -fpic

# Flags that only apply to PIE objects.
PIE_FLAGS	:= -fPIE -fpie

# `C_CXX_FLAGS` will be appended to `CFLAGS` and `CXXFLAGS`.
C_CXX_FLAGS := \
	-ggdb3 \
	-fstrict-aliasing \
	-fstack-protector-strong \
	-fno-omit-frame-pointer \
	-fdata-sections \
	-ffunction-sections \
	-D_GNU_SOURCE \
	-DVERSION=$(VERSION) \
	-DPATCHLEVEL=$(PATCHLEVEL) \
	-DSUBLEVEL=$(SUBLEVEL) \
	-DEXTRAVERSION="\"$(EXTRAVERSION)\"" \
	-DNAME="\"$(NAME)\""

C_CXX_FLAGS_RELEASE := -DNDEBUG
C_CXX_FLAGS_DEBUG :=

# Valgrind flags
VGFLAGS	:= \
	--leak-check=full \
	--show-leak-kinds=all \
	--track-origins=yes \
	--track-fds=yes \
	--error-exitcode=99 \
	-s

ifndef DEFAULT_OPTIMIZATION
	DEFAULT_OPTIMIZATION := -O2
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
	-Wno-used-but-marked-unused \
	-Wno-gnu-statement-expression


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


all: $(TARGET_BIN)

include $(BASE_DIR)/src/Makefile
include $(BASE_DIR)/test/Makefile

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
$(OBJ_CC): $(MAKEFILE_FILE) | $(DEP_DIRS)
$(OBJ_PRE_CC): $(MAKEFILE_FILE) | $(DEP_DIRS)


#
# Compile object from the main Makefile (the main Makefile is *this* Makefile).
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
$(TARGET_BIN): $(OBJ_CC) $(OBJ_PRE_CC)
	$(LD_PRINT)
	$(Q)$(LD) -shared $(PIC_FLAGS) $(LDFLAGS) $(^) -o "$(@)" $(LIB_LDFLAGS)


clean:
	$(Q)$(RM) -vf $(TARGET_BIN) $(OBJ_CC) $(OBJ_PRE_CC) $(TEST_EXE)

RELEASE_FILES := \
	.github \
	src \
	test \
	.gitignore \
	Makefile \
	README.md \
	LICENSE

release:
	+$(MAKE) RELEASE_MODE=1 clean;
	+$(MAKE) RELEASE_MODE=1;
	mkdir -vp hpc_emerg;
	cp -rfv $(RELEASE_FILES) hpc_emerg;
	tar -c hpc_emerg | gzip -9c > hpc_emerg.tar.gz;
	zip -9r hpc_emerg.zip hpc_emerg;
	rm -rf hpc_emerg;
	sha1sum hpc_emerg.tar.gz hpc_emerg.zip $(TARGET_BIN);

.PHONY: all clean release
