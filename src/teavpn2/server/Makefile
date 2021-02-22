
DEP_DIRS += $(BASE_DEP_DIR)/src/teavpn2/server

OBJ_CC += $(BASE_DIR)/src/teavpn2/server/argv.o
OBJ_CC += $(BASE_DIR)/src/teavpn2/server/config.o
OBJ_CC += $(BASE_DIR)/src/teavpn2/server/entry.o

ifeq ($(UNAME_S),Linux)
	include $(BASE_DIR)/src/teavpn2/server/linux/Makefile
endif
