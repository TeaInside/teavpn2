
#
# @author Ammar Faizi <ammarfaizi2@gmail.com> https://www.facebook.com/ammarfaizi2
# @license GNU GPL-v3
#
# TeaVPN2
#

TARGET_BIN	= teavpn2
TEAVPN_SERVER_VERSION	= 0.0.1
TEAVPN_CLIENT_VERSION	= 0.0.1
SERVER_DEFAULT_CONFIG_FILE	= config/server.ini
CLIENT_DEFAULT_CONFIG_FILE	= config/client.ini

CC	:= cc
CXX	:= c++
LD	:= $(CXX)
VG	:= valgrind

BASE_DIR := $(dir $(realpath $(lastword $(MAKEFILE_LIST))))
BASE_DIR := $(strip $(patsubst %/, %, $(BASE_DIR)))
BASE_DEP_DIR := $(BASE_DIR)/.deps
MAKEFILE_FILE := $(lastword $(MAKEFILE_LIST))

WARN_FLAGS	:= \
	-Wall \
	-Wextra \
	-Wstrict-aliasing=3 \
	-Wformat \
	-Wformat-security \
	-Wformat-signedness \
	-Wsequence-point \
	-Wduplicated-cond \
	-Wduplicated-branches \
	-Wunsafe-loop-optimizations \
	-Wstack-usage=2097152 \
	-Wimplicit-fallthrough


USE_CLIENT	:= 1
USE_SERVER	:= 1

DEPFLAGS	 = -MT "$@" -MMD -MP -MF "$(@:$(BASE_DIR)/%.o=$(BASE_DEP_DIR)/%.d)"
LIB_LDFLAGS	:= -lpthread
LDFLAGS		:= -fPIE -fpie $(WARN_FLAGS)
CFLAGS		:= -fPIE -fpie -std=c11
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
	-DTEAVPN_SERVER_VERSION="\"$(TEAVPN_SERVER_VERSION)\"" \
	-DTEAVPN_CLIENT_VERSION="\"$(TEAVPN_CLIENT_VERSION)\""


ifdef NOTICE_STATIC_LEVEL
CCXXFLAGS := $(CCXXFLAGS) -DNOTICE_STATIC_LEVEL="$(NOTICE_STATIC_LEVEL)"
endif

ifdef NOTICE_ALWAYS_EXEC
CCXXFLAGS := $(CCXXFLAGS) -DNOTICE_ALWAYS_EXEC="$(NOTICE_ALWAYS_EXEC)"
endif

ifeq ($(RELEASE_MODE),1)
	LDFLAGS		+= $(LDFLAGS) -O3
	CCXXFLAGS	+= -O3 -DNDEBUG
else
	LDFLAGS		+= $(DEFAULT_OPTIMIZATION)
	CCXXFLAGS	+= \
		$(DEFAULT_OPTIMIZATION) \
		-ggdb3 \
		-grecord-gcc-switches \
		-DTEAVPN_DEBUG
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
OBJ_CC		:=
OBJ_PRE_CC	:=
OBJ_TMP_CC	:=
CFLAGS_TMP	:=
#######################################

all: $(TARGET_BIN)

include $(BASE_DIR)/src/teavpn2/Makefile
include $(BASE_DIR)/src/ext/Makefile

CFLAGS		:= $(INCLUDE_DIR) $(CFLAGS) $(CCXXFLAGS)
CXXFLAGS	:= $(INCLUDE_DIR) $(CXXFLAGS) $(CCXXFLAGS)

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

clean:
	@rm -rfv $(DEP_DIRS) $(OBJ_CC) $(OBJ_PRE_CC) $(TARGET_BIN)

server: $(TARGET_BIN)
	sudo $(VG) $(VGFLAGS) ./$(TARGET_BIN) server
