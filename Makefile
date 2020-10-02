

# Compiler and linker options.
CC     = cc
CXX    = c++
NASM   = nasm
LINKER = $(CXX)

# Source and include directories.
CUR_DIR     = $(abspath .)
SRC_DIR     = $(CUR_DIR)/src
INCLUDE_DIR = -I$(SRC_DIR)/include -I$(SRC_DIR)/include/third_party
SOURCES_DIR = $(SRC_DIR)/sources
ROOT_DEPDIR = $(CUR_DIR)/.deps

GLOBAL_SOURCE_DIR = $(SOURCES_DIR)/teavpn2/global
CLIENT_SOURCE_DIR = $(SOURCES_DIR)/teavpn2/client
SERVER_SOURCE_DIR = $(SOURCES_DIR)/teavpn2/server

ifndef DEFAULT_OPTIMIZATION
	DEFAULT_OPTIMIZATION = -O0
endif

ifeq ($(COVERAGE),1)
	COVERAGE_FLAG = -fprofile-arcs -ftest-coverage --coverage
else
	COVERAGE_FLAG = 
endif

# C/C++ compile flags.
CFLAGS   = -std=c99 $(INCLUDE_DIR) -c
CXXFLAGS = -std=c++17 $(INCLUDE_DIR) -D_GLIBCXX_ASSERTIONS -c

LIB_LDFLAGS    = -lpthread

ifeq ($(RELEASE_MODE),1)

	# Compile flags that apply to CC and CXX.
	CCXXFLAGS = -Wall -Wextra $(COVERAGE_FLAG) -s -fno-stack-protector -O3 -fPIC -fasynchronous-unwind-tables -fexceptions -mstackrealign -DNDEBUG -D_GNU_SOURCE -D_REENTRANT $(COVERAGE_FLAG)

	# Link flags
	LDFLAGS = -Wall -Wextra -O3 -fPIC $(COVERAGE_FLAG)

else

	# Compile flags that apply to CC and CXX.
	CCXXFLAGS = -Wall -Wextra $(COVERAGE_FLAG) -fstack-protector-strong -ggdb3 $(DEFAULT_OPTIMIZATION) -grecord-gcc-switches -fPIC -fasynchronous-unwind-tables -fexceptions -mstackrealign -D_GNU_SOURCE -D_REENTRANT -DTEAVPN_DEBUG -DDEBUG

	# Link flags
	LDFLAGS = -Wall -Wextra -ggdb3 $(DEFAULT_OPTIMIZATION) -fPIC $(COVERAGE_FLAG) 

endif

ifndef TEST_JOBS
	TEST_JOBS = 1
endif

CFLAGS   := $(CFLAGS) $(CCXXFLAGS)
CXXFLAGS := $(CXXFLAGS) $(CCXXFLAGS)

# Target compile.
CLIENT_BIN = $(CUR_DIR)/teavpn_client
SERVER_BIN = $(CUR_DIR)/teavpn_server


###################### Global Part ######################
# Source code that must be compiled for client and server.

# Global source code.
GLOBAL_CC_SOURCES   = $(shell find ${GLOBAL_SOURCE_DIR} -name '*.c')
GLOBAL_CXX_SOURCES  = $(shell find ${GLOBAL_SOURCE_DIR} -name '*.cc')
GLOBAL_CXX_SOURCES += $(shell find ${GLOBAL_SOURCE_DIR} -name '*.cpp')
GLOBAL_CXX_SOURCES += $(shell find ${GLOBAL_SOURCE_DIR} -name '*.cxx')

# Global objects.
GLOBAL_CC_OBJECTS   = $(GLOBAL_CC_SOURCES:%=%.o)
GLOBAL_CXX_OBJECTS  = $(GLOBAL_CXX_SOURCES:%=%.o)
GLOBAL_OBJECTS      = $(GLOBAL_CC_OBJECTS)
GLOBAL_OBJECTS     += $(GLOBAL_CXX_OBJECTS)

# Global depends directories.
GLOBAL_DIR_L     = $(shell find ${GLOBAL_SOURCE_DIR} -type d)
GLOBAL_DEPDIR    = $(GLOBAL_DIR_L:%=${ROOT_DEPDIR}/%)
GLOBAL_DEPFLAGS  = -MT $@ -MMD -MP -MF ${ROOT_DEPDIR}/$*.d
GLOBAL_DEPFILES  = $(GLOBAL_CC_SOURCES:%=${ROOT_DEPDIR}/%.d)
GLOBAL_DEPFILES += $(GLOBAL_CXX_SOURCES:%=${ROOT_DEPDIR}/%.d)
###################### End of Global Part ######################


###################### Client Part ######################
# Source code that must be compiled for client.

# Global source code.
CLIENT_CC_SOURCES   = $(shell find ${CLIENT_SOURCE_DIR} -name '*.c')
CLIENT_CXX_SOURCES  = $(shell find ${CLIENT_SOURCE_DIR} -name '*.cc')
CLIENT_CXX_SOURCES += $(shell find ${CLIENT_SOURCE_DIR} -name '*.cpp')
CLIENT_CXX_SOURCES += $(shell find ${CLIENT_SOURCE_DIR} -name '*.cxx')

# Global objects.
CLIENT_CC_OBJECTS   = $(CLIENT_CC_SOURCES:%=%.o)
CLIENT_CXX_OBJECTS  = $(CLIENT_CXX_SOURCES:%=%.o)
CLIENT_OBJECTS      = $(CLIENT_CC_OBJECTS)
CLIENT_OBJECTS     += $(CLIENT_CXX_OBJECTS)

# Global depends directories.
CLIENT_DIR_L     = $(shell find ${CLIENT_SOURCE_DIR} -type d)
CLIENT_DEPDIR    = $(CLIENT_DIR_L:%=${ROOT_DEPDIR}/%)
CLIENT_DEPFLAGS  = -MT $@ -MMD -MP -MF ${ROOT_DEPDIR}/$*.d
CLIENT_DEPFILES  = $(CLIENT_CC_SOURCES:%=${ROOT_DEPDIR}/%.d)
CLIENT_DEPFILES += $(CLIENT_CXX_SOURCES:%=${ROOT_DEPDIR}/%.d)
###################### End of Client Part ######################


###################### Server Part ######################
# Source code that must be compiled for client.

# Server source code.
SERVER_CC_SOURCES   = $(shell find ${SERVER_SOURCE_DIR} -name '*.c')
SERVER_CXX_SOURCES  = $(shell find ${SERVER_SOURCE_DIR} -name '*.cc')
SERVER_CXX_SOURCES += $(shell find ${SERVER_SOURCE_DIR} -name '*.cpp')
SERVER_CXX_SOURCES += $(shell find ${SERVER_SOURCE_DIR} -name '*.cxx')

# Server objects.
SERVER_CC_OBJECTS   = $(SERVER_CC_SOURCES:%=%.o)
SERVER_CXX_OBJECTS  = $(SERVER_CXX_SOURCES:%=%.o)
SERVER_OBJECTS      = $(SERVER_CC_OBJECTS)
SERVER_OBJECTS     += $(SERVER_CXX_OBJECTS)

# Server depends directories.
SERVER_DIR_L     = $(shell find ${SERVER_SOURCE_DIR} -type d)
SERVER_DEPDIR    = $(SERVER_DIR_L:%=${ROOT_DEPDIR}/%)
SERVER_DEPFLAGS  = -MT $@ -MMD -MP -MF ${ROOT_DEPDIR}/$*.d
SERVER_DEPFILES  = $(SERVER_CC_SOURCES:%=${ROOT_DEPDIR}/%.d)
SERVER_DEPFILES += $(SERVER_CXX_SOURCES:%=${ROOT_DEPDIR}/%.d)
###################### End of Server Part ######################


all: client server

.PHONY: deps_dir

deps_dir: $(GLOBAL_DEPDIR)


${ROOT_DEPDIR}:
	mkdir -pv $@


###################### Build global sources ######################
global: $(GLOBAL_OBJECTS)

$(GLOBAL_DEPDIR): | $(ROOT_DEPDIR)
	mkdir -pv $@

$(GLOBAL_CC_OBJECTS): Makefile | $(GLOBAL_DEPDIR)
	$(CC) $(GLOBAL_DEPFLAGS) $(CFLAGS) $(@:%.o=%) -o $@

$(GLOBAL_CXX_OBJECTS): Makefile | $(GLOBAL_DEPDIR)
	$(CXX) $(GLOBAL_DEPFLAGS) $(CXXFLAGS) $(@:%.o=%) -o $@

-include $(GLOBAL_DEPFILES)
###################### End of build global sources ######################



###################### Build client sources ######################
client: $(CLIENT_BIN)

$(CLIENT_DEPDIR): | $(ROOT_DEPDIR)
	mkdir -pv $@

$(CLIENT_CC_OBJECTS): Makefile | $(CLIENT_DEPDIR)
	$(CC) $(CLIENT_DEPFLAGS) $(CFLAGS) $(@:%.o=%) -o $@

$(CLIENT_CXX_OBJECTS): Makefile | $(CLIENT_DEPDIR)
	$(CXX) $(CLIENT_DEPFLAGS) $(CXXFLAGS) $(@:%.o=%) -o $@

-include $(CLIENT_DEPFILES)

$(CLIENT_BIN): Makefile $(GLOBAL_OBJECTS) $(CLIENT_OBJECTS)
	$(LINKER) $(LDFLAGS) -o $@ $(CLIENT_OBJECTS) $(GLOBAL_OBJECTS) $(LIB_LDFLAGS)
###################### End of build client sources ######################



###################### Build server sources ######################
server: $(SERVER_BIN)

$(SERVER_DEPDIR): | $(ROOT_DEPDIR)
	mkdir -pv $@

$(SERVER_CC_OBJECTS): Makefile | $(SERVER_DEPDIR)
	$(CC) $(SERVER_DEPFLAGS) $(CFLAGS) $(@:%.o=%) -o $@

$(SERVER_CXX_OBJECTS): Makefile | $(SERVER_DEPDIR)
	$(CXX) $(SERVER_DEPFLAGS) $(CXXFLAGS) $(@:%.o=%) -o $@

-include $(SERVER_DEPFILES)

$(SERVER_BIN): Makefile $(GLOBAL_OBJECTS) $(SERVER_OBJECTS)
	$(LINKER) $(LDFLAGS) -o $@ $(SERVER_OBJECTS) $(GLOBAL_OBJECTS) $(LIB_LDFLAGS)
###################### End of build server sources ######################

test: $(GLOBAL_OBJECTS) $(SERVER_OBJECTS) $(CLIENT_OBJECTS)
	@cd tests && \
	env INCLUDE_DIR="$(INCLUDE_DIR)" \
	CC="$(CC)" \
	CXX="$(CC)" \
	LIB_LDFLAGS="$(LIB_LDFLAGS)" \
	LDFLAGS="$(LDFLAGS)" \
	GLOBAL_OBJECTS="$(GLOBAL_OBJECTS)" \
	SERVER_OBJECTS="$(SERVER_OBJECTS)" \
	CLIENT_OBJECTS="$(CLIENT_OBJECTS)" \
	ROOT_DEPDIR="$(ROOT_DEPDIR)" \
	DEFAULT_OPTIMIZATION="$(DEFAULT_OPTIMIZATION)" \
	COVERAGE_FLAG="$(COVERAGE_FLAG)" \
	$(MAKE) -j $(TEST_JOBS) -f test.mk

test_clean:
	@cd tests && \
	env INCLUDE_DIR="$(INCLUDE_DIR)" \
	CC="$(CC)" \
	CXX="$(CC)" \
	LIB_LDFLAGS="$(LIB_LDFLAGS)" \
	LDFLAGS="$(LDFLAGS)" \
	GLOBAL_OBJECTS="$(GLOBAL_OBJECTS)" \
	SERVER_OBJECTS="$(SERVER_OBJECTS)" \
	CLIENT_OBJECTS="$(CLIENT_OBJECTS)" \
	CLEAN=1 \
	ROOT_DEPDIR="$(ROOT_DEPDIR)" \
	$(MAKE) -s --no-print-directory -j $(TEST_JOBS) -f test.mk

gcov: test $(SERVER_BIN) $(CLIENT_BIN)
	$(SERVER_BIN) -c config/server.ini
	$(CLIENT_BIN) -c config/client.ini
	find -O2 . \( -name '*.gcno' -o -name '*.gcda' \) | xargs gcov -xl




###################### Cleaning part ######################
clean: clean_global clean_client clean_server test_clean
	@rm -rfv $(ROOT_DEPDIR)

clean_gcov:
	@find -O2 . \( -name '*.gcno' -o -name '*.gcda' -o -name '*.gcov' \) | xargs rm -vf

clean_global:
	@rm -rfv $(GLOBAL_OBJECTS)
	@rm -rfv $(GLOBAL_DEPDIR)

clean_server:
	@rm -rfv $(SERVER_OBJECTS)
	@rm -rfv $(SERVER_BIN)
	@rm -rfv $(SERVER_DEPDIR)

clean_client:
	@rm -rfv $(CLIENT_OBJECTS)
	@rm -rfv $(CLIENT_BIN)
	@rm -rfv $(CLIENT_DEPDIR)
###################### End of cleaning part ######################
