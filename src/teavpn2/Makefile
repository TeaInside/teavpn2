
INCLUDE_DIR += -I$(BASE_DIR)/src/teavpn2/include
DEP_DIRS	+= $(BASE_DEP_DIR)/src/teavpn2

ifeq ($(USE_SERVER),1)
	include $(BASE_DIR)/src/teavpn2/server/Makefile
endif

ifeq ($(USE_CLIENT),1)
	include $(BASE_DIR)/src/teavpn2/client/Makefile
endif

include $(BASE_DIR)/src/teavpn2/lib/Makefile
include $(BASE_DIR)/src/teavpn2/net/Makefile

OBJ_TMP_CC	:= \
	$(BASE_DIR)/src/teavpn2/cpu.o \
	$(BASE_DIR)/src/teavpn2/license.o \
	$(BASE_DIR)/src/teavpn2/print.o

ifneq ($(DO_TEST),1)
	OBJ_TMP_CC += $(BASE_DIR)/src/teavpn2/main.o
endif

OBJ_PRE_CC	+= $(OBJ_TMP_CC)

$(OBJ_TMP_CC):
	@echo "   CC		" "$(@:$(BASE_DIR)/%=%)"
	@$(CC) $(DEPFLAGS) $(CFLAGS) -c $(@:.o=.c) -o $(@)
