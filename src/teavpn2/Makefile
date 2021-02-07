
INCLUDE_DIR	+= -I$(BASE_DIR)/src/teavpn2/include

ifeq ($(USE_SERVER),1)
	DEP_DIRS += $(BASE_DEP_DIR)/src/teavpn2/server
	include $(BASE_DIR)/src/teavpn2/server/Makefile
endif

ifeq ($(USE_CLIENT),1)
	DEP_DIRS += $(BASE_DEP_DIR)/src/teavpn2/client
	include $(BASE_DIR)/src/teavpn2/client/Makefile
endif

DEP_DIRS	+= $(BASE_DEP_DIR)/src/teavpn2
OBJ_CC		+= $(BASE_DIR)/src/teavpn2/main.o

