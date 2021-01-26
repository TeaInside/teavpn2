
#
# @author Ammar Faizi <ammarfaizi2@gmail.com> https://www.facebook.com/ammarfaizi2
# @license GNU GPL-v3
#

CC	:= cc
CXX	:= c++
LD	:= $(CXX)
VG	:= valgrind

BASE_DIR := $(dir $(realpath $(lastword $(MAKEFILE_LIST))))
BASE_DIR := $(strip $(patsubst %/, %, $(BASE_DIR)))

DEP_DIR := $(BASE_DIR)/.deps
SRC_DIR := $(BASE_DIR)/src
INCLUDE_DIR	:= \
	-I$(SRC_DIR)/include \
	-I$(SRC_DIR)/include/third_party


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
	-Wstack-usage=2097152


TARGET_BIN	:= teavpn2
USE_CLIENT	:= 1
USE_SERVER	:= 1
LIB_LDFLAGS	:= -lpthread
LDFLAGS		:= -fPIE -fpie $(WARN_FLAGS)
CFLAGS		:= -fPIE -fpie -std=c11
CXXFLAGS	:= -fPIE -fpie -std=c++2a
VGFLAGS		:= \
	--leak-check=full \
	--show-leak-kinds=all \
	--track-origins=yes \
	--track-fds=yes -s


ifndef DEFAULT_OPTIMIZATION
	DEFAULT_OPTIMIZATION = -O0
endif


# CCXXFLAGS is a flag that applies to CFLAGS and CXXFLAGS
CCXXFLAGS := \
	$(INCLUDE_DIR) \
	$(WARN_FLAGS) \
	-fstrict-aliasing \
	-fstack-protector-strong \
	-pedantic-errors \
	-D_GNU_SOURCE


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
	CCXXFLAGS += -D WIN32
	ifeq ($(PROCESSOR_ARCHITEW6432),AMD64)
		CCXXFLAGS += -D AMD64
	else
		ifeq ($(PROCESSOR_ARCHITECTURE),AMD64)
			CCXXFLAGS += -D AMD64
		endif
		ifeq ($(PROCESSOR_ARCHITECTURE),x86)
			CCXXFLAGS += -D IA32
		endif
	endif
else
	UNAME_S := $(shell uname -s)
	ifeq ($(UNAME_S),Linux)
		CCXXFLAGS += -D LINUX
	endif
	ifeq ($(UNAME_S),Darwin)
		CCXXFLAGS += -D OSX
	endif

	UNAME_P := $(shell uname -p)
	ifeq ($(UNAME_P),x86_64)
		CCXXFLAGS += -D AMD64
	endif
	ifneq ($(filter %86,$(UNAME_P)),)
		CCXXFLAGS += -D IA32
	endif
	ifneq ($(filter arm%,$(UNAME_P)),)
		CCXXFLAGS += -D ARM
	endif
endif

CFLAGS		+= $(CCXXFLAGS)
CXXFLAGS	+= $(CCXXFLAGS)


GLOBAL_SRC_DIR	:= $(SRC_DIR)/sources/teavpn2/global
CLIENT_SRC_DIR	:= $(SRC_DIR)/sources/teavpn2/client
SERVER_SRC_DIR	:= $(SRC_DIR)/sources/teavpn2/server

MAIN_FILE	:= $(SRC_DIR)/sources/teavpn2/main.c
MAIN_OBJ	:= $(SRC_DIR)/sources/teavpn2/main.o
MAIN_DEP_DIRS	:= $(SRC_DIR:$(BASE_DIR)/%=$(DEP_DIR)/src/sources/teavpn2/%)
DEPFLAGS	 = -MT "$@" -MMD -MP -MF "$(@:$(BASE_DIR)/%.o=$(DEP_DIR)/%.d)"



all: $(TARGET_BIN)

clean: clean_target clean_main clean_global clean_server



# Main file for entry point
# ================================================================
$(MAIN_DEP_DIRS):
	@mkdir -pv "$@"

$(MAIN_OBJ): $(MAIN_FILE) | $(MAIN_DEP_DIRS)
	@echo "   CC	" "$(@:$(BASE_DIR)/%=%)"
	@$(CC) $(DEPFLAGS) $(CFLAGS) -c $(@:.o=.c) -o $(@)

clean_main:
	rm -vf $(MAIN_OBJ)
# ================================================================



# Global module
# ================================================================
GLOBAL_SRC_CC	:= $(shell find "${GLOBAL_SRC_DIR}" -name '*.c')
GLOBAL_SRC_CXX	:= $(shell find "${GLOBAL_SRC_DIR}" -name '*.cpp')
GLOBAL_OBJ_CC	:= $(GLOBAL_SRC_CC:.c=.o)
GLOBAL_OBJ_CXX	:= $(GLOBAL_SRC_CXX:.cpp=.o)
GLOBAL_OBJ	:= $(strip $(GLOBAL_OBJ_CC) $(GLOBAL_OBJ_CXX))
GLOBAL_DEP_DIRS	:= $(shell find "${GLOBAL_SRC_DIR}" -type d)
GLOBAL_DEP_DIRS := $(GLOBAL_DEP_DIRS:$(BASE_DIR)/%=$(DEP_DIR)/%)

$(GLOBAL_DEP_DIRS):
	@mkdir -pv $(GLOBAL_DEP_DIRS)

$(GLOBAL_OBJ_CC): $(GLOBAL_SRC_CC) | $(GLOBAL_DEP_DIRS)
	@echo "   CC	" "$(@:$(BASE_DIR)/%=%)"
	@$(CC) $(DEPFLAGS) $(CFLAGS) -c $(@:.o=.c) -o $(@)

$(GLOBAL_OBJ_CXX): $(GLOBAL_SRC_CXX) | $(GLOBAL_DEP_DIRS)
	@echo "   CC	" "$(@:$(BASE_DIR)/%=%)"
	@$(CXX) $(DEPFLAGS) $(CFLAGS) -c $(@:.o=.c) -o $(@)

clean_global:
	rm -vf $(GLOBAL_OBJ)
# ================================================================



# Server module
# ================================================================
SERVER_SRC_CC	:= $(shell find "${SERVER_SRC_DIR}" -name '*.c')
SERVER_SRC_CXX	:= $(shell find "${SERVER_SRC_DIR}" -name '*.cpp')
SERVER_OBJ_CC	:= $(SERVER_SRC_CC:.c=.o)
SERVER_OBJ_CXX	:= $(SERVER_SRC_CXX:.cpp=.o)
SERVER_OBJ	:= $(strip $(SERVER_OBJ_CC) $(SERVER_OBJ_CXX))
SERVER_DEP_DIRS	:= $(shell find "${SERVER_SRC_DIR}" -type d)
SERVER_DEP_DIRS := $(SERVER_DEP_DIRS:$(BASE_DIR)/%=$(DEP_DIR)/%)

$(SERVER_DEP_DIRS):
	@mkdir -pv $(SERVER_DEP_DIRS)

$(SERVER_OBJ_CC): $(SERVER_SRC_CC) | $(SERVER_DEP_DIRS)
	@echo "   CC	" "$(@:$(BASE_DIR)/%=%)"
	@$(CC) $(DEPFLAGS) $(CFLAGS) -c $(@:.o=.c) -o $(@)

$(SERVER_OBJ_CXX): $(SERVER_SRC_CXX) | $(SERVER_DEP_DIRS)
	@echo "   CC	" "$(@:$(BASE_DIR)/%=%)"
	@$(CXX) $(DEPFLAGS) $(CFLAGS) -c $(@:.o=.c) -o $(@)

clean_server:
	rm -vf $(SERVER_OBJ)
# ================================================================



# Server module
# ================================================================
CLIENT_SRC_CC	:= $(shell find "${CLIENT_SRC_DIR}" -name '*.c')
CLIENT_SRC_CXX	:= $(shell find "${CLIENT_SRC_DIR}" -name '*.cpp')
CLIENT_OBJ_CC	:= $(CLIENT_SRC_CC:.c=.o)
CLIENT_OBJ_CXX	:= $(CLIENT_SRC_CXX:.cpp=.o)
CLIENT_OBJ	:= $(strip $(CLIENT_OBJ_CC) $(CLIENT_OBJ_CXX))
CLIENT_DEP_DIRS	:= $(shell find "${CLIENT_SRC_DIR}" -type d)
CLIENT_DEP_DIRS := $(CLIENT_DEP_DIRS:$(BASE_DIR)/%=$(DEP_DIR)/%)

$(CLIENT_DEP_DIRS):
	@mkdir -pv $(CLIENT_DEP_DIRS)

$(CLIENT_OBJ_CC): $(CLIENT_SRC_CC) | $(CLIENT_DEP_DIRS)
	@echo "   CC	" "$(@:$(BASE_DIR)/%=%)"
	@$(CC) $(DEPFLAGS) $(CFLAGS) -c $(@:.o=.c) -o $(@)

$(CLIENT_OBJ_CXX): $(CLIENT_SRC_CXX) | $(CLIENT_DEP_DIRS)
	@echo "   CC	" "$(@:$(BASE_DIR)/%=%)"
	@$(CXX) $(DEPFLAGS) $(CFLAGS) -c $(@:.o=.c) -o $(@)

clean_client:
	rm -vf $(CLIENT_OBJ)
# ================================================================



# Link the binary
# ================================================================
$(TARGET_BIN): $(MAIN_OBJ) $(GLOBAL_OBJ) $(SERVER_OBJ) $(CLIENT_OBJ)
	@echo "   LD	" "$(@)"
	@$(LD) $(LDFLAGS) "$(MAIN_OBJ)" \
	$(GLOBAL_OBJ) $(SERVER_OBJ) $(CLIENT_OBJ) -o "$@" $(LIB_LDFLAGS)


clean_target:
	rm -vf $(TARGET_BIN)
# ================================================================
