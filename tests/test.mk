

CRITERION_DIR      = criterion-v2.3.3
CRITERION_TAR      = criterion-v2.3.3-linux-x86_64.tar.bz2

INCLUDE_DIR       := $(INCLUDE_DIR:-I%=-I../%) -I$(CRITERION_DIR)/include
SOURCES_DIR        = sources
BIN_DIR            = .bin

UNIT_TESTS         = $(shell find ${SOURCES_DIR} -mindepth 1 -maxdepth 1 -type d)

LD_LIBRARY_PATH    = $(CRITERION_DIR)/lib
CFLAGS             = $(DEFAULT_OPTIMIZATION) -ggdb3 -grecord-gcc-switches -fstack-protector-strong -fPIC -fasynchronous-unwind-tables $(INCLUDE_DIR)
LDFLAGS           := $(LDFLAGS)
LIB_LDFLAGS       := -L$(LD_LIBRARY_PATH) -lcriterion

GLOBAL_OBJECTS    := $(GLOBAL_OBJECTS:%=../%)
SERVER_OBJECTS    := $(SERVER_OBJECTS:%=../%)
CLIENT_OBJECTS    := $(CLIENT_OBJECTS:%=../%)

ROOT_DEPDIR       := ../$(ROOT_DEPDIR)/test

MAKEFILE_DEPS      = test.mk Makefile ../Makefile

ifeq ($(CLEAN),1)
	DSECTION = clean
	DO_TEST  = false
else
	DSECTION = all
	DO_TEST  = true
endif

all: $(UNIT_TESTS)

$(CRITERION_DIR):
	@tar -xvf $(CRITERION_TAR)

$(BIN_DIR):
	@mkdir -pv $(BIN_DIR)

###################### Unit Tests ######################
.PHONY: $(UNIT_TESTS)

$(UNIT_TESTS): $(CRITERION_DIR) $(BIN_DIR)
	@if $(DO_TEST); then \
		(test -f ${@}/info.sh && exec sh ${@}/info.sh) || true; \
	fi;

	@env \
	TARGET_TEST="$(@)" \
	CFLAGS="$(CFLAGS)" \
	INCLUDE_DIR="$(INCLUDE_DIR)" \
	SOURCES_DIR="$(SOURCES_DIR)" \
	LDFLAGS="$(LDFLAGS)" \
	LIB_LDFLAGS="$(LIB_LDFLAGS)" \
	CC="$(CC)" \
	CXX="$(CC)" \
	GLOBAL_OBJECTS="$(GLOBAL_OBJECTS)" \
	SERVER_OBJECTS="$(SERVER_OBJECTS)" \
	CLIENT_OBJECTS="$(CLIENT_OBJECTS)" \
	BIN_DIR="$(BIN_DIR)" \
	ROOT_DEPDIR="$(ROOT_DEPDIR)" \
	MAKEFILE_DEPS="$(MAKEFILE_DEPS)" \
	$(MAKE) -s --no-print-directory -j $(TEST_JOBS) $(DSECTION);

	@if $(DO_TEST); then \
		env LD_LIBRARY_PATH="$(LD_LIBRARY_PATH)" \
		valgrind --show-leak-kinds=all \
		$(BIN_DIR)/$(@:sources/%=%).test; \
	else \
		true; \
	fi;

####################### End of Unit Tests ######################
