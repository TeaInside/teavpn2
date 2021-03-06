
DEP_DIRS	+= $(BASE_DEP_DIR)/src/teavpn2/server

OBJ_TMP_CC	:= \
	$(BASE_DIR)/src/teavpn2/server/argv.o \
	$(BASE_DIR)/src/teavpn2/server/config.o \
	$(BASE_DIR)/src/teavpn2/server/entry.o \
	$(BASE_DIR)/src/teavpn2/server/help.o

OBJ_PRE_CC	+= $(OBJ_TMP_CC)

$(OBJ_TMP_CC):
	@echo "   CC		" "$(@:$(BASE_DIR)/%=%)"
	@$(CC) $(DEPFLAGS) $(CFLAGS) -c $(@:.o=.c) -o $(@)
