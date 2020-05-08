
BASEDIR = $(shell pwd)

# Compiler and linker options.
CC = gcc
CXX = g++
LINKER = g++
NASM = nasm
INCLUDE_DIR = -I${BASEDIR}/include
LINK_LIBRARIES = -lpthread
LINK_FLAGS = 
COMPILE_FLAGS = 
RELEASE_MODE = 0
CC_STD_FLAGS = -std=c99
CXX_STD_FLAGS = -std=c++17

# Target compile.
CLIENT_BIN = teavpn_client
SERVER_BIN = teavpn_server

ifeq (${RELEASE_MODE},1)
	NASM_FLAGS = -felf64 -O3
	LINKER_FLAGS = -Wl,-R -Wl,${BASEDIR} -rdynamic -fno-stack-protector -Ofast ${CONSTANTS}
	CC_COMPILER_FLAGS = -rdynamic ${INCLUDE_DIR} ${CC_STD_FLAGS} -fPIC -fno-stack-protector -Ofast ${CONSTANTS} -c
	CXX_COMPILER_FLAGS = -rdynamic ${INCLUDE_DIR} ${STD_FLAGS} -fPIC -fno-stack-protector -Ofast ${CONSTANTS} -c
else
	NASM_FLAGS = -felf64 -g -O0
	LINKER_FLAGS = -Wl,-R -Wl,${BASEDIR} -rdynamic -fstack-protector-strong -ggdb3 -O0 -DICETEA_DEBUG ${CONSTANTS}
	CC_COMPILER_FLAGS = -rdynamic ${INCLUDE_DIR} ${CC_STD_FLAGS} -fPIC -fstack-protector-strong -ggdb3 -O0 -DICETEA_DEBUG ${CONSTANTS} -c
	CXX_COMPILER_FLAGS = -rdynamic ${INCLUDE_DIR} ${CXX_STD_FLAGS} -fPIC -fstack-protector-strong -ggdb3 -O0 -DICETEA_DEBUG ${CONSTANTS} -c
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
GLOBAL_C_OBJECTS = $(GLOBAL_SOURCES:%=%.o)
GLOBAL_CXX_OBJECTS = $(GLOBAL_CXX_SOURCES:%=%.o)
GLOBAL_ASM_OBJECTS = $(GLOBAL_ASM_SOURCES:%=%.o)

# Global depends directories.
GLOBAL_DEPDIR = .deps/src/global
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

# Server depends directories.
SERVER_DEPDIR = .deps/src/server
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

# Client depends directories.
CLIENT_DEPDIR = .deps/src/client
CLIENT_DEPFLAGS = -MT $@ -MMD -MP -MF ${ROOT_DEPDIR}/$*.d
CLIENT_DEPFILES = ${CLIENT_C_SOURCES:%=${ROOT_DEPDIR}/%.d}
CLIENT_DEPFILES+= ${CLIENT_CXX_SOURCES:%=${ROOT_DEPDIR}/%.d}
###################### End of Client Section ######################



### Run the compile rules ###
all: ${CLIENT_BIN} ${SERVER_BIN}

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

${SERVER_BIN}: ${SERVER_C_OBJECTS} ${SERVER_CXX_OBJECTS} ${SERVER_ASM_OBJECTS}
	${LINKER} ${LINKER_FLAGS} ${SERVER_C_OBJECTS} ${SERVER_CXX_OBJECTS} ${SERVER_ASM_OBJECTS} -o ${SERVER_BIN}
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

${CLIENT_BIN}: ${CLIENT_C_OBJECTS} ${CLIENT_CXX_OBJECTS} ${CLIENT_ASM_OBJECTS}
	${LINKER} ${LINKER_FLAGS} ${CLIENT_C_OBJECTS} ${CLIENT_CXX_OBJECTS} ${CLIENT_ASM_OBJECTS} -o ${CLIENT_BIN}
###################### End of build client sources ######################


###################### Cleaning section ######################
clean: clean_global clean_client clean_server

clean_global:
	rm -rfv ${GLOBAL_C_OBJECTS} ${GLOBAL_CXX_OBJECTS} ${GLOBAL_ASM_OBJECTS}
	rm -rfv ${GLOBAL_DEPDIR}

clean_server:
	rm -rfv ${SERVER_C_OBJECTS} ${SERVER_CXX_OBJECTS} ${SERVER_ASM_OBJECTS}
	rm -rfv ${SERVER_BIN}
	rm -rfv ${SERVER_DEPDIR}

clean_client:
	rm -rfv ${CLIENT_C_OBJECTS} ${CLIENT_CXX_OBJECTS} ${CLIENT_ASM_OBJECTS}
	rm -rfv ${CLIENT_BIN}
	rm -rfv ${CLIENT_DEPDIR}
###################### End of leaning section ######################
