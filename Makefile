
BASEDIR = $(shell pwd)

# Compiler and linker options.
CC = gcc
CXX = g++
LINKER = g++
NASM = nasm
INCLUDE_DIR = -I${BASEDIR}/include -I${BASEDIR}/include/third_party
LINK_LIBRARIES = -lpthread
RELEASE_MODE = 0
CC_COMPILE_FLAGS = -std=c11
CXX_COMPILE_FLAGS = -std=c++17 -D_GLIBCXX_ASSERTIONS
ALL_COMPILE_FLAGS = -rdynamic -fPIC -fasynchronous-unwind-tables -fexceptions -mstackrealign -D_GNU_SOURCE -D_REENTRANT

RELEASE_COMPILE_FLAG = -fno-stack-protector -Ofast 
DEBUG_COMPILE_FLAG = -fstack-protector-strong -ggdb3 -O0 -DTEAVPN_DEBUG -grecord-gcc-switches

# Target compile.
CLIENT_BIN = teavpn_client
SERVER_BIN = teavpn_server

ifeq (${RELEASE_MODE},1)
NASM_FLAGS = -felf64 -O3
LINKER_FLAGS = -Wl,-R -Wl,${BASEDIR} ${LINK_FLAGS} ${ALL_COMPILE_FLAGS}
CC_COMPILER_FLAGS = ${INCLUDE_DIR} ${CC_COMPILE_FLAGS} ${ALL_COMPILE_FLAGS} ${RELEASE_COMPILE_FLAG} -c
CXX_COMPILER_FLAGS = ${INCLUDE_DIR} ${CXX_COMPILE_FLAGS} ${ALL_COMPILE_FLAGS} ${RELEASE_COMPILE_FLAG} -c
else
NASM_FLAGS = -felf64 -g -O0
LINKER_FLAGS = -Wl,-R -Wl,${BASEDIR} ${DEBUG_COMPILE_FLAG}
CC_COMPILER_FLAGS = ${INCLUDE_DIR}  ${CC_COMPILE_FLAGS} ${ALL_COMPILE_FLAGS} ${DEBUG_COMPILE_FLAG} -c
CXX_COMPILER_FLAGS = ${INCLUDE_DIR} ${CXX_COMPILE_FLAGS} ${ALL_COMPILE_FLAGS} ${DEBUG_COMPILE_FLAG} -c
endif

ROOT_DEPDIR = .deps

GLOBAL_SRC_DIR = src/global
CLIENT_SRC_DIR = src/client
SERVER_SRC_DIR = src/server

###################### Global Section ######################
# Source code that must be compiled for client and server.

# Global source code.
GLOBAL_C_SOURCES = $(shell find ${GLOBAL_SRC_DIR} -name '*.c')
GLOBAL_CXX_SOURCES = $(shell find ${GLOBAL_SRC_DIR} -name '*.cc')
GLOBAL_CXX_SOURCES+= $(shell find ${GLOBAL_SRC_DIR} -name '*.cpp')
GLOBAL_CXX_SOURCES+= $(shell find ${GLOBAL_SRC_DIR} -name '*.cxx')
GLOBAL_ASM_SOURCES+= $(shell find ${GLOBAL_SRC_DIR} -name '*.asm')

# Global objects.
GLOBAL_C_OBJECTS = $(GLOBAL_C_SOURCES:%=%.o)
GLOBAL_CXX_OBJECTS = $(GLOBAL_CXX_SOURCES:%=%.o)
GLOBAL_ASM_OBJECTS = $(GLOBAL_ASM_SOURCES:%=%.o)
GLOBAL_OBJECTS = $(GLOBAL_C_OBJECTS)
GLOBAL_OBJECTS+= $(GLOBAL_CXX_OBJECTS)
GLOBAL_OBJECTS+= $(GLOBAL_ASM_OBJECTS)

# Global depends directories.
GLOBAL_DIR_L = $(shell find ${GLOBAL_SRC_DIR} -type d)
GLOBAL_DEPDIR = ${GLOBAL_DIR_L:%=${ROOT_DEPDIR}/%}
GLOBAL_DEPFLAGS = -MT $@ -MMD -MP -MF ${ROOT_DEPDIR}/$*.d
GLOBAL_DEPFILES = ${GLOBAL_C_SOURCES:%=${ROOT_DEPDIR}/%.d}
GLOBAL_DEPFILES+= ${GLOBAL_CXX_SOURCES:%=${ROOT_DEPDIR}/%.d}
###################### End of Global Section ######################




###################### Server Section ######################
# Source code that must be compiled for server.
# Server source code.
SERVER_C_SOURCES = $(shell find src/server -name '*.c')
SERVER_CXX_SOURCES = $(shell find src/server -name '*.cc')
SERVER_CXX_SOURCES+= $(shell find src/server -name '*.cpp')
SERVER_CXX_SOURCES+= $(shell find src/server -name '*.cxx')
SERVER_ASM_SOURCES+= $(shell find src/server -name '*.asm')

# Server objects.
SERVER_C_OBJECTS = $(SERVER_C_SOURCES:%=%.o)
SERVER_CXX_OBJECTS = $(SERVER_CXX_SOURCES:%=%.o)
SERVER_ASM_OBJECTS = $(SERVER_ASM_SOURCES:%=%.o)
SERVER_OBJECTS = $(SERVER_C_OBJECTS)
SERVER_OBJECTS+= $(SERVER_CXX_OBJECTS)
SERVER_OBJECTS+= $(SERVER_ASM_OBJECTS)

# Server depends directories.
SERVER_DIR_L = $(shell find ${SERVER_SRC_DIR} -type d)
SERVER_DEPDIR = ${SERVER_DIR_L:%=${ROOT_DEPDIR}/%}
SERVER_DEPFLAGS = -MT $@ -MMD -MP -MF ${ROOT_DEPDIR}/$*.d
SERVER_DEPFILES = ${SERVER_C_SOURCES:%=${ROOT_DEPDIR}/%.d}
SERVER_DEPFILES+= ${SERVER_CXX_SOURCES:%=${ROOT_DEPDIR}/%.d}
###################### End of Server Section ######################




###################### Client Section ######################
# Source code that must be compiled for client.

# Client source code.
CLIENT_C_SOURCES = $(shell find src/client -name '*.c')
CLIENT_CXX_SOURCES = $(shell find src/client -name '*.cc')
CLIENT_CXX_SOURCES+= $(shell find src/client -name '*.cpp')
CLIENT_CXX_SOURCES+= $(shell find src/client -name '*.cxx')
CLIENT_ASM_SOURCES+= $(shell find src/server -name '*.asm')

# Client objects.
CLIENT_C_OBJECTS = $(CLIENT_C_SOURCES:%=%.o)
CLIENT_CXX_OBJECTS = $(CLIENT_CXX_SOURCES:%=%.o)
CLIENT_ASM_OBJECTS = $(CLIENT_ASM_SOURCES:%=%.o)
CLIENT_OBJECTS = $(CLIENT_C_OBJECTS)
CLIENT_OBJECTS+= $(CLIENT_CXX_OBJECTS)
CLIENT_OBJECTS+= $(CLIENT_ASM_OBJECTS)

# Client depends directories.
CLIENT_DIR_L = $(shell find ${CLIENT_SRC_DIR} -type d)
CLIENT_DEPDIR = ${CLIENT_DIR_L:%=${ROOT_DEPDIR}/%}
CLIENT_DEPFLAGS = -MT $@ -MMD -MP -MF ${ROOT_DEPDIR}/$*.d
CLIENT_DEPFILES = ${CLIENT_C_SOURCES:%=${ROOT_DEPDIR}/%.d}
CLIENT_DEPFILES+= ${CLIENT_CXX_SOURCES:%=${ROOT_DEPDIR}/%.d}
###################### End of Client Section ######################


### Run the compile rules ###
all: ${SERVER_BIN} ${CLIENT_BIN} 

.PHONY: deps_dir

deps_dir: ${GLOBAL_DEPDIR} ${CLIENT_DEPDIR} ${SERVER_DEPDIR}

${ROOT_DEPDIR}:
	mkdir -pv $@

###################### Build global sources ######################
${GLOBAL_DEPDIR}: | ${ROOT_DEPDIR}
	mkdir -pv $@

${GLOBAL_C_OBJECTS}: | ${GLOBAL_DEPDIR}
	${CC} ${GLOBAL_DEPFLAGS} ${CC_COMPILER_FLAGS} ${@:%.o=%} -o $@

${GLOBAL_CXX_OBJECTS}: | ${GLOBAL_DEPDIR}
	${CXX} ${GLOBAL_DEPFLAGS} ${CXX_COMPILER_FLAGS} ${@:%.o=%} -o $@

${GLOBAL_ASM_OBJECTS}:
	${NASM} ${NASM_FLAGS} ${@:%.o=%} -o $@

-include ${GLOBAL_DEPFILES}

global: ${GLOBAL_C_OBJECTS} ${GLOBAL_CXX_OBJECTS} ${GLOBAL_ASM_OBJECTS}
###################### End of build global sources ######################


###################### Build server sources ######################
server: ${SERVER_BIN}

${SERVER_DEPDIR}: | ${ROOT_DEPDIR}
	mkdir -pv $@

${SERVER_C_OBJECTS}: | ${SERVER_DEPDIR}
	${CC} ${SERVER_DEPFLAGS} ${CC_COMPILER_FLAGS} ${@:%.o=%} -o $@

${SERVER_CXX_OBJECTS}: | ${SERVER_DEPDIR}
	${CXX} ${SERVER_DEPFLAGS} ${CXX_COMPILER_FLAGS} ${@:%.o=%} -o $@

${SERVER_ASM_OBJECTS}:
	${NASM} ${NASM_FLAGS} ${@:%.o=%} -o $@

-include ${SERVER_DEPFILES}

${SERVER_BIN}: ${GLOBAL_OBJECTS} ${SERVER_OBJECTS}
	${LINKER} ${LINKER_FLAGS} ${GLOBAL_OBJECTS} ${SERVER_OBJECTS} -o ${SERVER_BIN} ${LINK_LIBRARIES}
###################### End of build server sources ######################


###################### Build client sources ######################
client: ${CLIENT_BIN}

${CLIENT_DEPDIR}: | ${ROOT_DEPDIR}
	mkdir -pv $@

${CLIENT_C_OBJECTS}: | ${CLIENT_DEPDIR}
	${CC} ${CLIENT_DEPFLAGS} ${CC_COMPILER_FLAGS} ${@:%.o=%} -o $@

${CLIENT_CXX_OBJECTS}: | ${CLIENT_DEPDIR}
	${CXX} ${CLIENT_DEPFLAGS} ${CXX_COMPILER_FLAGS} ${@:%.o=%} -o $@

${CLIENT_ASM_OBJECTS}:
	${NASM} ${NASM_FLAGS} ${@:%.o=%} -o $@

-include ${CLIENT_DEPFILES}

${CLIENT_BIN}: ${GLOBAL_OBJECTS} ${CLIENT_OBJECTS}
	${LINKER} ${LINKER_FLAGS} ${GLOBAL_OBJECTS} ${CLIENT_OBJECTS} -o ${CLIENT_BIN} ${LINK_LIBRARIES}
###################### End of build client sources ######################


###################### Cleaning section ######################
clean: clean_global clean_client clean_server
	rm -rfv ${ROOT_DEPDIR}

clean_global:
	rm -rfv ${GLOBAL_OBJECTS}
	rm -rfv ${GLOBAL_DEPDIR}

clean_server:
	rm -rfv ${SERVER_OBJECTS}
	rm -rfv ${SERVER_BIN}
	rm -rfv ${SERVER_DEPDIR}

clean_client:
	rm -rfv ${CLIENT_OBJECTS}
	rm -rfv ${CLIENT_BIN}
	rm -rfv ${CLIENT_DEPDIR}
###################### End of cleaning section ######################
