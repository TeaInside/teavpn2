
DEP_DIRS	+= $(BASE_DEP_DIR)/src/teavpn2/server

ifeq ($(UNAME_S),Linux)
	include $(BASE_DIR)/src/teavpn2/server/linux/Makefile
endif

OBJ_TMP_CC	:= \
	$(BASE_DIR)/src/teavpn2/server/argv.o \
	$(BASE_DIR)/src/teavpn2/server/auth.o \
	$(BASE_DIR)/src/teavpn2/server/config.o \
	$(BASE_DIR)/src/teavpn2/server/entry.o \
	$(BASE_DIR)/src/teavpn2/server/help.o \
	$(BASE_DIR)/src/teavpn2/server/tcp.o

OBJ_PRE_CC	+= $(OBJ_TMP_CC)
$(OBJ_TMP_CC):
	@echo "   CC		" "$(@:$(BASE_DIR)/%=%)"
	@$(CC) $(DEPFLAGS) $(CFLAGS) $(CFLAGS_TMP) \
	-DSERVER_DEFAULT_CONFIG_FILE="\"$(SERVER_DEFAULT_CONFIG_FILE)\"" \
	-c $(@:.o=.c) -o $(@)
