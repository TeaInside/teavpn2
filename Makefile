
# Compiler and linker options.
CC          := cc
CXX         := c++
LD          := $(CXX)
BASE_DIR    := $(dir $(realpath $(lastword $(MAKEFILE_LIST))))
BASE_DIR    := $(strip $(patsubst %/, %, $(BASE_DIR)))
SRC_DIR     := $(BASE_DIR)/src
DEP_DIR     := $(BASE_DIR)/.deps
INCLUDE_DIR := -I$(SRC_DIR)/include               \
               -I$(SRC_DIR)/include/third_party

GLOBAL_SRC_DIR := $(SRC_DIR)/sources/teavpn2/global
CLIENT_SRC_DIR := $(SRC_DIR)/sources/teavpn2/client
SERVER_SRC_DIR := $(SRC_DIR)/sources/teavpn2/server

## Target file ##
SERVER_BIN  := tvpnserver
CLIENT_BIN  := tvpnclient


## Default flags ##
LDFLAGS     := -Wall -Wextra
CFLAGS      := -Wall -Wextra -fPIC -std=c99 $(INCLUDE_DIR) 
CXXFLAGS    := -Wall -Wextra -fPIC -std=c++17 $(INCLUDE_DIR) \
               -D_GLIBCXX_ASSERTIONS

## Link library flags
LIB_LDFLAGS := -lpthread

ifndef DEFAULT_OPTIMIZATION
    DEFAULT_OPTIMIZATION = -O0
endif

## CCXXFLAGS are the flags that apply to CC and CXX.
ifeq ($(RELEASE_MODE),1)
    CCXXFLAGS := -O3                             \
                 -s                              \
                 -fstack-protector               \
                 -DNDEBUG                        \
                 -D_GNU_SOURCE                   \
                 -D_REENTRANT

    LDFLAGS   := -O3 -fPIC
else
    CCXXFLAGS := $(DEFAULT_OPTIMIZATION)         \
                 -fexceptions                    \
                 -fstack-protector-strong        \
                 -fasynchronous-unwind-tables    \
                 -grecord-gcc-switches           \
                 -ggdb3                          \
                 -DTEAVPN_DEBUG                  \
                 -D_GNU_SOURCE                   \
                 -D_REENTRANT

    LDFLAGS   := $(DEFAULT_OPTIMIZATION) -fPIC
endif

ifdef COVERAGE
    ifeq ($(COVERAGE),1)
        COVERAGE_FLAG := --coverage
        LDFLAGS       := --coverage
        LIB_LDFLAGS   := $(LIB_LDFLAGS) -lgcov
        CCXXFLAGS     := $(CCXXFLAGS) -fprofile-arcs -ftest-coverage
    else
        COVERAGE_FLAG :=
    endif
endif

CFLAGS   := $(strip $(COVERAGE_FLAG) $(CFLAGS) $(CCXXFLAGS))
CXXFLAGS := $(strip $(COVERAGE_FLAG) $(CXXFLAGS) $(CCXXFLAGS))


#
# Global Source Code
#
# Modules that are required by $(SERVER_BIN) and $(CLIENT_BIN)
#
GLOBAL_SRC_CC    := $(shell find ${GLOBAL_SRC_DIR} -name '*.c')
GLOBAL_SRC_CXX   := $(shell find ${GLOBAL_SRC_DIR} -name '*.cpp')
GLOBAL_OBJ_CC    := $(GLOBAL_SRC_CC:%=%.o)
GLOBAL_OBJ_CXX   := $(GLOBAL_SRC_CXX:%=%.o)
GLOBAL_OBJ       := $(strip $(GLOBAL_OBJ_CC) $(GLOBAL_OBJ_CXX))
GLOBAL_SRC_DIRL  := $(shell find ${GLOBAL_SRC_DIR} -type d)
GLOBAL_DEP_DIRS  := $(GLOBAL_SRC_DIRL:$(BASE_DIR)/%=$(DEP_DIR)/%)
GLOBAL_DEP_FLAGS  = -MT $(@) -MMD -MP -MF $(DEP_DIR)/$(@:$(BASE_DIR)/%.o=%.d)
GLOBAL_DEP_FILES := $(GLOBAL_SRC_CC) $(GLOBAL_SRC_CXX)
GLOBAL_DEP_FILES := $(GLOBAL_DEP_FILES:$(BASE_DIR)/%=$(DEP_DIR)/%.d)


#
# Server Source Code
#
# Modules that are required by $(SERVER_BIN)
#
SERVER_SRC_CC    := $(shell find ${SERVER_SRC_DIR} -name '*.c')
SERVER_SRC_CXX   := $(shell find ${SERVER_SRC_DIR} -name '*.cpp')
SERVER_OBJ_CC    := $(SERVER_SRC_CC:%=%.o)
SERVER_OBJ_CXX   := $(SERVER_SRC_CXX:%=%.o)
SERVER_OBJ       := $(strip $(SERVER_OBJ_CC) $(SERVER_OBJ_CXX))
SERVER_SRC_DIRL  := $(shell find ${SERVER_SRC_DIR} -type d)
SERVER_DEP_DIRS  := $(SERVER_SRC_DIRL:$(BASE_DIR)/%=$(DEP_DIR)/%)
SERVER_DEP_FLAGS  = -MT $(@) -MMD -MP -MF $(DEP_DIR)/$(@:$(BASE_DIR)/%.o=%.d)
SERVER_DEP_FILES := $(SERVER_SRC_CC) $(SERVER_SRC_CXX)
SERVER_DEP_FILES := $(SERVER_DEP_FILES:$(BASE_DIR)/%=$(DEP_DIR)/%.d)


#
# Client Source Code
#
# Modules that are required by $(CLIENT_BIN)
#
CLIENT_SRC_CC    := $(shell find ${CLIENT_SRC_DIR} -name '*.c')
CLIENT_SRC_CXX   := $(shell find ${CLIENT_SRC_DIR} -name '*.cpp')
CLIENT_OBJ_CC    := $(CLIENT_SRC_CC:%=%.o)
CLIENT_OBJ_CXX   := $(CLIENT_SRC_CXX:%=%.o)
CLIENT_OBJ       := $(strip $(CLIENT_OBJ_CC) $(CLIENT_OBJ_CXX))
CLIENT_SRC_DIRL  := $(shell find ${CLIENT_SRC_DIR} -type d)
CLIENT_DEP_DIRS  := $(CLIENT_SRC_DIRL:$(BASE_DIR)/%=$(DEP_DIR)/%)
CLIENT_DEP_FLAGS  = -MT $(@) -MMD -MP -MF $(DEP_DIR)/$(@:$(BASE_DIR)/%.o=%.d)
CLIENT_DEP_FILES := $(CLIENT_SRC_CC) $(CLIENT_SRC_CXX)
CLIENT_DEP_FILES := $(CLIENT_DEP_FILES:$(BASE_DIR)/%=$(DEP_DIR)/%.d)


all: server client
clean: clean_server clean_client clean_global


###########################################
# Build global modules
global: $(GLOBAL_OBJ)

$(GLOBAL_DEP_DIRS):
	@mkdir -pv $(@)

$(GLOBAL_OBJ_CC): $(MAKEFILE_LIST) | $(GLOBAL_DEP_DIRS)
	@echo "  CC   $(@:%.o=%)"
	@$(CC) $(GLOBAL_DEP_FLAGS) $(CFLAGS) -c $(@:%.o=%) -o $(@)

$(GLOBAL_OBJ_CXX): $(MAKEFILE_LIST) | $(GLOBAL_DEP_DIRS)
	@echo "  CXX  $(@:%.o=%)"
	@$(CXX) $(GLOBAL_DEP_FLAGS) $(CXXFLAGS) -c $(@:%.o=%) -o $(@)

-include $(GLOBAL_DEP_FILES)

clean_global:
	@rm -rfv $(GLOBAL_OBJ) $(GLOBAL_DEP_DIRS)
###########################################


###########################################
# Build server modules
server: $(SERVER_BIN)

$(SERVER_BIN): $(GLOBAL_OBJ) $(SERVER_OBJ)
	$(LD) $(LDFLAGS) $(GLOBAL_OBJ) $(SERVER_OBJ) -o $(@) $(LIB_LDFLAGS)

$(SERVER_DEP_DIRS):
	@mkdir -pv $(@)

$(SERVER_OBJ_CC): $(MAKEFILE_LIST) | $(SERVER_DEP_DIRS)
	@echo "  CC   $(@:%.o=%)"
	@$(CC) $(SERVER_DEP_FLAGS) $(CFLAGS) -c $(@:%.o=%) -o $(@)

$(SERVER_OBJ_CXX): $(MAKEFILE_LIST) | $(SERVER_DEP_DIRS)
	@echo "  CXX  $(@:%.o=%)"
	@$(CXX) $(SERVER_DEP_FLAGS) $(CXXFLAGS) -c $(@:%.o=%) -o $(@)

-include $(SERVER_DEP_FILES)

clean_server:
	@rm -rfv $(SERVER_OBJ) $(SERVER_DEP_DIRS) $(SERVER_BIN)
###########################################

###########################################
# Build client modules
client: $(CLIENT_BIN)

$(CLIENT_BIN): $(GLOBAL_OBJ) $(CLIENT_OBJ)
	$(LD) $(LDFLAGS) $(GLOBAL_OBJ) $(CLIENT_OBJ) -o $(@) $(LIB_LDFLAGS)

$(CLIENT_DEP_DIRS):
	@mkdir -pv $(@)

$(CLIENT_OBJ_CC): $(MAKEFILE_LIST) | $(CLIENT_DEP_DIRS)
	@echo "  CC   $(@:%.o=%)"
	@$(CC) $(CLIENT_DEP_FLAGS) $(CFLAGS) -c $(@:%.o=%) -o $(@)

$(CLIENT_OBJ_CXX): $(MAKEFILE_LIST) | $(CLIENT_DEP_DIRS)
	@echo "  CXX  $(@:%.o=%)"
	@$(CXX) $(CLIENT_DEP_FLAGS) $(CXXFLAGS) -c $(@:%.o=%) -o $(@)

-include $(CLIENT_DEP_FILES)
clean_client:
	@rm -rfv $(CLIENT_OBJ) $(CLIENT_DEP_DIRS) $(CLIENT_BIN)
###########################################


## TODO: Fix test command.
test:
	true
