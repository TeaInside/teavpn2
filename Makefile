
#
# @author Ammar Faizi <ammarfaizi2@gmail.com> https://www.facebook.com/ammarfaizi2
# @license GNU GPL-v2
#
# TeaVPN2 - Fast and Free VPN Software
#

VERSION = 0
PATCHLEVEL = 0
SUBLEVEL = 1
EXTRAVERSION = -rc1
NAME = Frozen Wasteland

SERVER_DEFAULT_CFG_FILE = config/server.ini
CLIENT_DEFAULT_CFG_FILE = config/client.ini

TARGET_BIN = teavpn2

CC	:= cc
CXX	:= c++
LD	:= $(CXX)
VG	:= valgrind

BASE_DIR := $(dir $(realpath $(lastword $(MAKEFILE_LIST))))
BASE_DIR := $(strip $(patsubst %/, %, $(BASE_DIR)))
BASE_DEP_DIR := $(BASE_DIR)/.deps
MAKEFILE_FILE := $(lastword $(MAKEFILE_LIST))

CC_BUILTIN_CONSTANTS := $(shell $(CC) -dM -E - < /dev/null)
CXX_BUILTIN_CONSTANTS := $(shell $(CXX) -dM -E - < /dev/null)

ifeq (,$(findstring __GNUC__,$(CXX_BUILTIN_CONSTANTS)))
$(error I want __GNUC__!)
endif

ifneq ($(DO_TEST),1)
	ifneq (,$(findstring __GNUC__,$(CC_BUILTIN_CONSTANTS)))
		ifneq (,$(findstring __clang__,$(CC_BUILTIN_CONSTANTS)))
			# Clang
			WARN_FLAGS	:= \
				-Wall \
				-Werror \
				-Wextra \
				-Weverything \
				-Wno-disabled-macro-expansion
		else
			# Pure GCC
			WARN_FLAGS	:= \
				-Wall \
				-Werror \
				-Wextra \
				-Wstrict-aliasing=3 \
				-Wformat \
				-Wformat-security \
				-Wformat-signedness \
				-Wsequence-point \
				-Wunsafe-loop-optimizations \
				-Wstack-usage=2097152
		endif
	else
	$(error I want __GNUC__!)
	endif
endif

USE_CLIENT	:= 1
USE_SERVER	:= 1

DEPFLAGS	 = -MT "$@" -MMD -MP -MF "$(@:$(BASE_DIR)/%.o=$(BASE_DEP_DIR)/%.d)"
LIB_LDFLAGS	:= -lpthread
LDFLAGS		:= -fPIE -fpie
CFLAGS		:= -fPIE -fpie # -std=c11
CXXFLAGS	:= -fPIE -fpie -std=c++2a
VGFLAGS		:= \
	--leak-check=full \
	--show-leak-kinds=all \
	--track-origins=yes \
	--track-fds=yes \
	--error-exitcode=99 \
	--exit-on-first-error=yes -s

ifndef DEFAULT_OPTIMIZATION
	DEFAULT_OPTIMIZATION = -O0
endif

# CCXXFLAGS is a flag that applies to CFLAGS and CXXFLAGS
CCXXFLAGS := \
	$(WARN_FLAGS) \
	-fstrict-aliasing \
	-fstack-protector-strong \
	-pedantic-errors \
	-D_GNU_SOURCE \
	-DVERSION=$(VERSION) \
	-DPATCHLEVEL=$(PATCHLEVEL) \
	-DSUBLEVEL=$(SUBLEVEL) \
	-DEXTRAVERSION=\"$(EXTRAVERSION)\" \
	-DSERVER_DEFAULT_CFG_FILE=\"$(SERVER_DEFAULT_CFG_FILE)\" \
	-DCLIENT_DEFAULT_CFG_FILE=\"$(CLIENT_DEFAULT_CFG_FILE)\"

ifeq ($(RELEASE_MODE),1)
	REL := --- Build release mode
	LDFLAGS		+= $(LDFLAGS) -O3
	CCXXFLAGS	+= -O3 -DNDEBUG

	ifndef NOTICE_MAX_LEVEL
		NOTICE_MAX_LEVEL = 4
	endif

	ifndef NOTICE_ALWAYS_EXEC
		NOTICE_ALWAYS_EXEC = 0
	endif

	ifndef DEFAULT_NOTICE_LEVEL
		DEFAULT_NOTICE_LEVEL = 4
	endif
else
	REL := --- Build debug mode
	LDFLAGS		+= $(DEFAULT_OPTIMIZATION)
	CCXXFLAGS	+= \
		$(DEFAULT_OPTIMIZATION) \
		-ggdb3 \
		-grecord-gcc-switches \
		-DTEAVPN_DEBUG

	ifndef NOTICE_MAX_LEVEL
		NOTICE_MAX_LEVEL = 10
	endif

	ifndef NOTICE_ALWAYS_EXEC
		NOTICE_ALWAYS_EXEC = 1
	endif

	ifndef DEFAULT_NOTICE_LEVEL
		DEFAULT_NOTICE_LEVEL = 5
	endif
endif

CCXXFLAGS := \
	$(CCXXFLAGS) \
	-DNOTICE_MAX_LEVEL="$(NOTICE_MAX_LEVEL)" \
	-DNOTICE_ALWAYS_EXEC="$(NOTICE_ALWAYS_EXEC)" \
	-DDEFAULT_NOTICE_LEVEL="$(DEFAULT_NOTICE_LEVEL)"

ifeq ($(SANITIZE),1)
	REL += with sanitize
	CCXXFLAGS := \
		$(CCXXFLAGS) \
		-fsanitize=undefined \
		-fno-sanitize-recover=undefined
	LIB_LDFLAGS += -lubsan
endif

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

#######################################
# Force these to be a simple variable
TESTS		:=
OBJ_CC		:=
OBJ_PRE_CC	:=
OBJ_TMP_CC	:=
CFLAGS_TMP	:=
#######################################

all: $(TARGET_BIN)
	@echo $(REL)

include $(BASE_DIR)/src/teavpn2/Makefile
include $(BASE_DIR)/src/ext/Makefile

CFLAGS		:= $(INCLUDE_DIR) $(CFLAGS) $(CCXXFLAGS)
CXXFLAGS	:= $(INCLUDE_DIR) $(CXXFLAGS) $(CCXXFLAGS)

include $(BASE_DIR)/tests/Makefile

$(TARGET_BIN): $(OBJ_CC) $(OBJ_PRE_CC)
	@echo "   LD		" "$(@)"
	@$(LD) $(LDFLAGS) $(OBJ_CC) $(OBJ_PRE_CC) -o "$@" $(LIB_LDFLAGS)
	@chmod a+x teavpn2 || true

$(DEP_DIRS):
	@echo "   MKDIR	" "$(@:$(BASE_DIR)/%=%)"
	@mkdir -p $(@)

$(OBJ_CC): $(MAKEFILE_FILE) | $(DEP_DIRS)
	@echo "   CC		" "$(@:$(BASE_DIR)/%=%)"
	@$(CC) $(DEPFLAGS) $(CFLAGS) -c $(@:.o=.c) -o $(@)

$(OBJ_PRE_CC): $(MAKEFILE_FILE) | $(DEP_DIRS)

-include $(OBJ_CC:$(BASE_DIR)/%.o=$(BASE_DEP_DIR)/%.d)
-include $(OBJ_PRE_CC:$(BASE_DIR)/%.o=$(BASE_DEP_DIR)/%.d)

clean: clean_test
	@rm -rfv $(DEP_DIRS) $(OBJ_CC) $(OBJ_PRE_CC) $(TARGET_BIN)

server: $(TARGET_BIN)
	sudo $(VG) $(VGFLAGS) ./$(TARGET_BIN) server

client: $(TARGET_BIN)
	sudo $(VG) $(VGFLAGS) ./$(TARGET_BIN) client
