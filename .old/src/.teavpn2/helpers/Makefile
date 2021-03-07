
DEP_DIRS += $(BASE_DEP_DIR)/src/teavpn2/helpers

OBJ_CC += \
	$(BASE_DIR)/src/teavpn2/helpers/shell.o \
	$(BASE_DIR)/src/teavpn2/helpers/string.o \
	$(BASE_DIR)/src/teavpn2/helpers/arena.o \
	$(BASE_DIR)/src/teavpn2/helpers/debug.o

ifeq ($(UNAME_S),Linux)
	include $(BASE_DIR)/src/teavpn2/helpers/linux/Makefile
endif
