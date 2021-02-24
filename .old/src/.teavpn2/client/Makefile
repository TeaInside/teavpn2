
DEP_DIRS += $(BASE_DEP_DIR)/src/teavpn2/client

ifeq ($(UNAME_S),Linux)
	include $(BASE_DIR)/src/teavpn2/client/linux/Makefile
endif


OBJ_TMP_CC	:= \
	$(BASE_DIR)/src/teavpn2/client/entry.o \

OBJ_PRE_CC	+= $(OBJ_TMP_CC)

$(OBJ_TMP_CC):
	@echo "   CC		" "$(@:$(BASE_DIR)/%=%)"
	@$(CC) $(DEPFLAGS) $(CFLAGS) -c $(@:.o=.c) -o $(@)

#################################################################
CFLAGS_TMP	:= \
	-DSERVER_DEFAULT_CONFIG_FILE="\"$(SERVER_DEFAULT_CONFIG_FILE)\"" \
	-DCLIENT_DEFAULT_CONFIG_FILE="\"$(CLIENT_DEFAULT_CONFIG_FILE)\""


OBJ_TMP_CC	:= \
	$(BASE_DIR)/src/teavpn2/client/help.o \
	$(BASE_DIR)/src/teavpn2/client/argv.o \
	$(BASE_DIR)/src/teavpn2/client/config.o

OBJ_PRE_CC	+= $(OBJ_TMP_CC)

$(OBJ_TMP_CC):
	@echo "   CC		" "$(@:$(BASE_DIR)/%=%)"
	@$(CC) $(DEPFLAGS) $(CFLAGS) $(CFLAGS_TMP) -c $(@:.o=.c) -o $(@)
#################################################################