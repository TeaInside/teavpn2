#
# SPDX-License-Identifier: GPL-2.0
#
# @author Ammar Faizi <ammarfaizi2@gmail.com> https://www.facebook.com/ammarfaizi2
# @license GNU GPL-v2
#
# TeaVPN2 - Fast and Free VPN Software
#

VERSION	= 0
PATCHLEVEL = 1
SUBLEVEL = 0
EXTRAVERSION =
NAME = Blue Tea
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
MSHARED_BIN	:= libteavpn2.so


#
# Default config file
#
SERVER_DEF_CFG_FILE := /etc/teavpn2/server.ini
CLIENT_DEF_CFG_FILE := /etc/teavpn2/client.ini


#
# Package files
#
PACKAGE_FILES := \
	$(TARGET_BIN) \
	$(LICENSES_DIR) \
	$(BASE_DIR)/LICENSES \
	$(BASE_DIR)/README.md \
	$(BASE_DIR)/config \
	$(BASE_DIR)/data




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
		-Wno-language-extension-token \
		-Wno-used-but-marked-unused

	CFLAGS		:=
	CXXFLAGS	:=
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

	CFLAGS		:= -fchecking=2 -fcompare-debug
	CXXFLAGS	:= -fchecking=2 -fcompare-debug
endif



#
# File dependency generator (especially for headers)
#
DEPFLAGS = -MT "$@" -MMD -MP -MF "$(@:$(BASE_DIR)/%.o=$(BASE_DEP_DIR)/%.d)"



LIB_LDFLAGS	:= -lpthread -lssl -lcrypto
LDFLAGS		:= -fPIC -fpic -ggdb3
CFLAGS		+= -fPIC -fpic -ggdb3
CXXFLAGS	+= -fPIC -fpic -ggdb3 -std=c++2a
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
# `CCXXFLAGS` is a flag that applies to `LDFLAGS`, `CFLAGS` and `CXXFLAGS`
#
ifeq ($(RELEASE_MODE),1)
	CCXXFLAGS	:= -O3 -DNDEBUG


	ifndef NOTICE_DEFAULT_LEVEL
		NOTICE_DEFAULT_LEVEL = 3
	endif

	ifndef NOTICE_MAX_LEVEL
		NOTICE_MAX_LEVEL = 5
	endif
else
	CCXXFLAGS	:= \
		$(DEFAULT_OPTIMIZATION) \
		-grecord-gcc-switches \
		-DTEAVPN_DEBUG \
		-DTEAVPN2_DEBUG


	#
	# Always sanitize debug build
	#
	ifndef SANITIZE
		SANITIZE = 1
	endif

	ifndef NOTICE_DEFAULT_LEVEL
		NOTICE_DEFAULT_LEVEL = 5
	endif

	ifndef NOTICE_MAX_LEVEL
		NOTICE_MAX_LEVEL = 10
	endif
endif



ifeq ($(SANITIZE),1)
	CCXXFLAGS := \
		$(CCXXFLAGS) \
		-fsanitize=undefined \
		-fno-sanitize-recover=undefined
	LIB_LDFLAGS += -lubsan
endif



CCXXFLAGS := \
	$(WARN_FLAGS) \
	$(CCXXFLAGS) \
	-fstrict-aliasing \
	-fstack-protector-strong \
	-fno-omit-frame-pointer \
	-pedantic-errors \
	-D_GNU_SOURCE \
	-DVERSION=$(VERSION) \
	-DPATCHLEVEL=$(PATCHLEVEL) \
	-DSUBLEVEL=$(SUBLEVEL) \
	-DEXTRAVERSION="\"$(EXTRAVERSION)\"" \
	-DNAME="\"$(NAME)\"" \
	-DSERVER_DEF_CFG_FILE="\"$(SERVER_DEF_CFG_FILE)\"" \
	-DCLIENT_DEF_CFG_FILE="\"$(CLIENT_DEF_CFG_FILE)\""



ifeq ($(OS),Windows_NT)
	CCXXFLAGS += -DWIN32
	ifeq ($(PROCESSOR_ARCHITEW6432),AMD64)
		CCXXFLAGS += -DAMD64
	else
		ifeq ($(PROCESSOR_ARCHITECTURE),AMD64)
			CCXXFLAGS += -DAMD64
		endif
		ifeq ($(PROCESSOR_ARCHITECTURE),x86)
			CCXXFLAGS += -DIA32
		endif
	endif
else
	UNAME_S := $(shell uname -s)
	ifeq ($(UNAME_S),Linux)
		CCXXFLAGS += -DLINUX
	endif
	ifeq ($(UNAME_S),Darwin)
		CCXXFLAGS += -DOSX
	endif

	UNAME_P := $(shell uname -p)
	ifeq ($(UNAME_P),x86_64)
		CCXXFLAGS += -DAMD64
	endif
	ifneq ($(filter %86,$(UNAME_P)),)
		CCXXFLAGS += -DIA32
	endif
	ifneq ($(filter arm%,$(UNAME_P)),)
		CCXXFLAGS += -DARM
	endif
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
TEST_TVAR	:=
TEST_EXEC	:=
OBJ_CC		:=
OBJ_PRE_CC	:=
OBJ_TMP_CC	:=
CFLAGS_TMP	:=
SHARED_LIB	:=
#######################################



ifneq ($(words $(subst :, ,$(BASE_DIR))), 1)
$(error Source directory cannot contain spaces or colons)
endif



all: $(TARGET_BIN)

include $(BASE_DIR)/src/ext/Makefile
include $(BASE_DIR)/src/teavpn2/Makefile
include $(BASE_DIR)/tests/Makefile

CFLAGS		:= $(INCLUDE_DIR) $(CFLAGS) $(CCXXFLAGS)
CXXFLAGS	:= $(INCLUDE_DIR) $(CXXFLAGS) $(CCXXFLAGS)
LDFLAGS		:= $(LDFLAGS) $(CCXXFLAGS)


$(MSHARED_BIN): $(OBJ_CC) $(OBJ_PRE_CC)
	$(S)echo "   LD		" "$(@)"
	$(Q)$(LD) $(LDFLAGS) $(OBJ_CC) $(OBJ_PRE_CC) -shared -o "$@" $(LIB_LDFLAGS)



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
$(TEST_OBJ): $(MAKEFILE_FILE) | $(DEP_DIRS)
$(FWTEST_OBJ): $(MAKEFILE_FILE) | $(DEP_DIRS)


#
# Include dependency
#
-include $(OBJ_CC:$(BASE_DIR)/%.o=$(BASE_DEP_DIR)/%.d)
-include $(OBJ_PRE_CC:$(BASE_DIR)/%.o=$(BASE_DEP_DIR)/%.d)



clean: clean_test
	$(Q)rm -rfv $(DEP_DIRS) $(OBJ_CC) $(OBJ_PRE_CC) $(TARGET_BIN)



clean_all: clean clean_test



release_pack:
	+$(MAKE) --no-print-directory RELEASE_MODE=1
	+$(MAKE) --no-print-directory test
	+$(MAKE) --no-print-directory __build_release_pack RELEASE_MODE=1



__build_release_pack: $(TARGET_BIN) $(PACKAGE_FILES)
	$(Q)strip -s $(TARGET_BIN);
	$(Q)mkdir -pv "$(PACKAGE_NAME)";
	$(Q)cp -vrf $(PACKAGE_FILES) "$(PACKAGE_NAME)/";
	$(Q)tar -c "$(PACKAGE_NAME)/" | gzip -9c > "$(PACKAGE_NAME).tar.gz";
	$(Q)md5sum "$(PACKAGE_NAME).tar.gz" > "$(PACKAGE_NAME).tar.gz.md5sum";
	$(Q)sha1sum "$(PACKAGE_NAME).tar.gz" > "$(PACKAGE_NAME).tar.gz.sha1sum";
	$(Q)sha256sum "$(PACKAGE_NAME).tar.gz" > "$(PACKAGE_NAME).tar.gz.sha256sum";
	$(Q)rm -rf "$(PACKAGE_NAME)";
	ls -l "$(PACKAGE_NAME).tar.gz"*;



.PHONY: all clean clean_all release_pack __build_release_pack
