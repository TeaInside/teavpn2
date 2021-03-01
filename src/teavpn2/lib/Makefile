
DEP_DIRS	+= $(BASE_DEP_DIR)/src/teavpn2/lib
OBJ_TMP_CC	:= \
	$(BASE_DIR)/src/teavpn2/lib/arena.o \
	$(BASE_DIR)/src/teavpn2/lib/hashtable.o \
	$(BASE_DIR)/src/teavpn2/lib/shell.o \
	$(BASE_DIR)/src/teavpn2/lib/string.o

OBJ_PRE_CC	+= $(OBJ_TMP_CC)

$(OBJ_TMP_CC):
	@echo "   CC		" "$(@:$(BASE_DIR)/%=%)"
	@$(CC) $(DEPFLAGS) $(CFLAGS) -c $(@:.o=.c) -o $(@)
