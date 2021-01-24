
# Compiler and linker options.
CC              := cc
CXX             := c++
LD              := $(CXX)
VALGRIND        := valgrind

BASE_DIR        := $(dir $(realpath $(lastword $(MAKEFILE_LIST))))
BASE_DIR        := $(strip $(patsubst %/, %, $(BASE_DIR)))

DEP_DIR         := $(BASE_DIR)/.deps
SRC_DIR         := $(BASE_DIR)/src
INCLUDE_DIR     := -I$(SRC_DIR)/include               \
                   -I$(SRC_DIR)/include/third_party

## Target executable ##
TARGET_BIN		:= $(BASE_DIR)/teavpn2

## Default flags ##
LDFLAGS         := -Wall -Wextra -fPIE -fpie
CFLAGS          := -Wall -Wextra -fPIE -fpie -std=c11 $(INCLUDE_DIR) 
CXXFLAGS        := -Wall -Wextra -fPIE -fpie -std=c++2a $(INCLUDE_DIR)


## Link library flags
LIB_LDFLAGS     := -lpthread


ifndef DEFAULT_OPTIMIZATION
    DEFAULT_OPTIMIZATION = -O0
endif

## CCXXFLAGS is a group of flags that applies to CC and CXX.
ifeq ($(RELEASE_MODE),1)
    CCXXFLAGS   :=  -O3                         \
                    -DNDEBUG

    LDFLAGS     :=  $(LDFLAGS)                  \
                    -O3
else
    CCXXFLAGS   :=  $(DEFAULT_OPTIMIZATION)     \
                    -ggdb3                      \
                    -grecord-gcc-switches       \
                    -DTEAVPN_DEBUG

    LDFLAGS     :=  $(LDFLAGS)                  \
                    $(DEFAULT_OPTIMIZATION)
endif


CCXXFLAGS       :=  $(CCXXFLAGS)                \
                    -fexceptions                \
                    -fstack-protector-strong    \
                    -D_GNU_SOURCE               \
                    -D_REENTRANT


CFLAGS          := $(strip $(COVERAGE_FLAG) $(CFLAGS) $(CCXXFLAGS))
CXXFLAGS        := $(strip $(COVERAGE_FLAG) $(CXXFLAGS) $(CCXXFLAGS))
VALGRIND_FLAGS  := --leak-check=full --show-leak-kinds=all --track-origins=yes --track-fds=yes -s

export CC
export CXX
export LD
export VALGRIND

export BASE_DIR
export DEP_DIR
export SRC_DIR
export INCLUDE_DIR

export DEFAULT_OPTIMIZATION
export CFLAGS
export CXXFLAGS
export LDFLAGS
export VALGRIND_FLAGS


MAIN_FILE        := $(SRC_DIR)/sources/teavpn2/main.c
MAIN_OBJ         := $(SRC_DIR)/sources/teavpn2/main.o
GLOBAL_SRC_DIR   := $(SRC_DIR)/sources/teavpn2/global
CLIENT_SRC_DIR   := $(SRC_DIR)/sources/teavpn2/client
SERVER_SRC_DIR   := $(SRC_DIR)/sources/teavpn2/server

#########################################################
GLOBAL_SRC_CC    := $(shell find "${GLOBAL_SRC_DIR}" -name '*.c')
GLOBAL_SRC_CXX   := $(shell find "${GLOBAL_SRC_DIR}" -name '*.cpp')

GLOBAL_OBJ_CC    := $(GLOBAL_SRC_CC:%=%.o)
GLOBAL_OBJ_CXX   := $(GLOBAL_SRC_CXX:%=%.o)
GLOBAL_OBJ       := $(strip $(GLOBAL_OBJ_CC) $(GLOBAL_OBJ_CXX))

GLOBAL_SRC_DIRL  := $(shell find "${GLOBAL_SRC_DIR}" -type d)
GLOBAL_DEP_DIRS  := $(GLOBAL_SRC_DIRL:$(BASE_DIR)/%=$(DEP_DIR)/%)
GLOBAL_DEP_FLAGS  = -MT $(@) -MMD -MP -MF $(DEP_DIR)/$(@:$(BASE_DIR)/%.o=%.d)
GLOBAL_DEP_FILES := $(GLOBAL_SRC_CC) $(GLOBAL_SRC_CXX)
GLOBAL_DEP_FILES := $(GLOBAL_DEP_FILES:$(BASE_DIR)/%=$(DEP_DIR)/%.d)
#########################################################

#########################################################
SERVER_SRC_CC    := $(shell find "${SERVER_SRC_DIR}" -name '*.c')
SERVER_SRC_CXX   := $(shell find "${SERVER_SRC_DIR}" -name '*.cpp')

SERVER_OBJ_CC    := $(SERVER_SRC_CC:%=%.o)
SERVER_OBJ_CXX   := $(SERVER_SRC_CXX:%=%.o)
SERVER_OBJ       := $(strip $(SERVER_OBJ_CC) $(SERVER_OBJ_CXX))

SERVER_SRC_DIRL  := $(shell find "${SERVER_SRC_DIR}" -type d)
SERVER_DEP_DIRS  := $(SERVER_SRC_DIRL:$(BASE_DIR)/%=$(DEP_DIR)/%)
SERVER_DEP_FLAGS  = -MT $(@) -MMD -MP -MF $(DEP_DIR)/$(@:$(BASE_DIR)/%.o=%.d)
SERVER_DEP_FILES := $(SERVER_SRC_CC) $(SERVER_SRC_CXX)
SERVER_DEP_FILES := $(SERVER_DEP_FILES:$(BASE_DIR)/%=$(DEP_DIR)/%.d)
#########################################################

#########################################################
CLIENT_SRC_CC    := $(shell find "${CLIENT_SRC_DIR}" -name '*.c')
CLIENT_SRC_CXX   := $(shell find "${CLIENT_SRC_DIR}" -name '*.cpp')

CLIENT_OBJ_CC    := $(CLIENT_SRC_CC:%=%.o)
CLIENT_OBJ_CXX   := $(CLIENT_SRC_CXX:%=%.o)
CLIENT_OBJ       := $(strip $(CLIENT_OBJ_CC) $(CLIENT_OBJ_CXX))

CLIENT_SRC_DIRL  := $(shell find "${CLIENT_SRC_DIR}" -type d)
CLIENT_DEP_DIRS  := $(CLIENT_SRC_DIRL:$(BASE_DIR)/%=$(DEP_DIR)/%)
CLIENT_DEP_FLAGS  = -MT $(@) -MMD -MP -MF $(DEP_DIR)/$(@:$(BASE_DIR)/%.o=%.d)
CLIENT_DEP_FILES := $(CLIENT_SRC_CC) $(CLIENT_SRC_CXX)
CLIENT_DEP_FILES := $(CLIENT_DEP_FILES:$(BASE_DIR)/%=$(DEP_DIR)/%.d)
#########################################################

all: $(TARGET_BIN)

clean: clean_server clean_client clean_global clean_main

#########################################################
$(GLOBAL_DEP_DIRS):
	@mkdir -pv $(@)

$(GLOBAL_OBJ_CC): $(MAKEFILE_LIST) | $(GLOBAL_DEP_DIRS)
	$(CC) $(GLOBAL_DEP_FLAGS) $(CFLAGS) -c $(@:%.o=%) -o $(@)

$(GLOBAL_OBJ_CXX): $(MAKEFILE_LIST) | $(GLOBAL_DEP_DIRS)
	$(CXX) $(GLOBAL_DEP_FLAGS) $(CXXFLAGS) -c $(@:%.o=%) -o $(@)

clean_global:
	@rm -rfv $(GLOBAL_OBJ) $(GLOBAL_DEP_DIRS)

-include $(GLOBAL_DEP_FILES)
#########################################################


#########################################################
$(SERVER_DEP_DIRS):
	@mkdir -pv $(@)

$(SERVER_OBJ_CC): $(MAKEFILE_LIST) | $(SERVER_DEP_DIRS)
	$(CC) $(SERVER_DEP_FLAGS) $(CFLAGS) -c $(@:%.o=%) -o $(@)

$(SERVER_OBJ_CXX): $(MAKEFILE_LIST) | $(SERVER_DEP_DIRS)
	$(CXX) $(SERVER_DEP_FLAGS) $(CXXFLAGS) -c $(@:%.o=%) -o $(@)

clean_server:
	@rm -rfv $(SERVER_OBJ) $(SERVER_DEP_DIRS)

-include $(SERVER_DEP_FILES)
#########################################################


#########################################################
$(CLIENT_DEP_DIRS):
	@mkdir -pv $(@)

$(CLIENT_OBJ_CC): $(MAKEFILE_LIST) | $(CLIENT_DEP_DIRS)
	$(CC) $(CLIENT_DEP_FLAGS) $(CFLAGS) -c $(@:%.o=%) -o $(@)

$(CLIENT_OBJ_CXX): $(MAKEFILE_LIST) | $(CLIENT_DEP_DIRS)
	$(CXX) $(CLIENT_DEP_FLAGS) $(CXXFLAGS) -c $(@:%.o=%) -o $(@)

clean_client:
	@rm -rfv $(CLIENT_OBJ) $(CLIENT_DEP_DIRS)

-include $(CLIENT_DEP_FILES)
#########################################################

$(MAIN_OBJ): $(MAIN_FILE)
	$(CC) -MT $(@) -MMD -MP -MF $(DEP_DIR)/$(@:$(BASE_DIR)/%.o=%.d) \
	$(CFLAGS) -c $(MAIN_FILE) -o $(@)

clean_main:
	@rm -vf $(MAIN_OBJ)

$(TARGET_BIN): $(GLOBAL_OBJ) $(SERVER_OBJ) $(CLIENT_OBJ) $(MAIN_OBJ)
	$(LD) $(LDFLAGS) $(GLOBAL_OBJ) $(SERVER_OBJ) $(CLIENT_OBJ) $(MAIN_OBJ) \
	-o $(@) $(LIB_LDFLAGS)

server_run: $(TARGET_BIN)
	sudo $(VALGRIND) $(VALGRIND_FLAGS) $(TARGET_BIN) server
