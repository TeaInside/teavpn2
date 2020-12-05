
# Compiler and linker options.
CC              := cc
CXX             := cxx
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
                    -s                          \
                    -DNDEBUG

    LDFLAGS     :=  -O3 -s
else
    CCXXFLAGS   :=  $(DEFAULT_OPTIMIZATION)     \
                    -ggdb3                      \
                    -grecord-gcc-switches       \
                    -DTEAVPN_DEBUG

    LDFLAGS     :=  $(DEFAULT_OPTIMIZATION)
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


all: $(TARGET_BIN)

$(GLOBAL_OBJ):

$(SERVER_OBJ):

$(CLIENT_OBJ):

$(TARGET_BIN): $(GLOBAL_OBJ) $(SERVER_OBJ) $(CLIENT_OBJ)
	$(LD) $(LDFLAGS) -o $(@) $(LIB_LDFLAGS)

