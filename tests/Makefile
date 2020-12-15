
ifndef BASE_DIR
	BASE_DIR    := $(dir $(realpath $(lastword $(MAKEFILE_LIST))))/..
	BASE_DIR    := $(strip $(patsubst %/, %, $(realpath $(BASE_DIR))))
endif

TEST_DIR       := $(BASE_DIR)/tests
TEST_SRC_DIR   := $(TEST_DIR)/sources
TEST_BIN_DIR   := $(TEST_DIR)/.bin
UNIT_TESTS     := $(shell find "${TEST_SRC_DIR}" -mindepth 1 -maxdepth 1 -type d)


############################################
## TODO: Add unit tests support for other architectures.
##
## Current supported arch: x86_64
##
############################################
CRITERION_DIR   = $(TEST_DIR)/criterion-v2.3.3
CRITERION_TAR   = $(TEST_DIR)/criterion-v2.3.3-linux-x86_64.tar.bz2
INCLUDE_DIR    := $(INCLUDE_DIR) -I$(CRITERION_DIR)/include
CCXXFLAGS      := $(DEFAULT_OPTIMIZATION)         \
                  -fexceptions                    \
                  -fstack-protector-strong        \
                  -fasynchronous-unwind-tables    \
                  -fprofile-arcs                  \
                  -ftest-coverage                 \
                  -grecord-gcc-switches           \
                  -ggdb3                          \
                  -DTEAVPN_DEBUG                  \
                  -D_GNU_SOURCE                   \
                  -D_REENTRANT

CFLAGS         := -Wall -Wextra -fPIC -std=c99 $(INCLUDE_DIR) 
CXXFLAGS       := -Wall -Wextra -fPIC -std=c++17 $(INCLUDE_DIR) \
                  -D_GLIBCXX_ASSERTIONS

COVERAGE_FLAG  := --coverage
CFLAGS         := $(strip $(COVERAGE_FLAG) $(CFLAGS) $(CCXXFLAGS))
CXXFLAGS       := $(strip $(COVERAGE_FLAG) $(CXXFLAGS) $(CCXXFLAGS))
LIB_LDFLAGS    := $(LIB_LDFLAGS) -L"$(CRITERION_DIR)/lib" -lcriterion -lgcov
LD_PRELOAD     := $(CRITERION_DIR)/lib/libcriterion.so.3.1.0

export TEST_DIR
export TEST_SRC_DIR
export TEST_BIN_DIR
export TEST_DEP_DIR
export CFLAGS
export CXXFLAGS
export LIB_LDFLAGS
export INCLUDE_DIR
export CRITERION_DIR
export LD_PRELOAD
export VALGRIND
export VALGRIND_FLAGS

TEST_CMD := all

ifdef CLEAN_TEST
    ifneq ($(CLEAN_TEST),0)
        TEST_CMD := clean
    endif
endif

all: $(UNIT_TESTS)

.PHONY: $(UNIT_TESTS)

$(CRITERION_DIR):
	@tar -xvf $(CRITERION_TAR) -C $(TEST_DIR)

$(TEST_BIN_DIR):
	@mkdir -pv $(@)

$(UNIT_TESTS): | $(CRITERION_DIR) $(TEST_DEP_DIR) $(TEST_BIN_DIR)
	@$(MAKE)                                       \
	--no-print-directory                           \
	-C $(@) $(TEST_CMD)
