
DEP_DIRS	+= $(BASE_DEP_DIR)/src/teavpn2/net/linux
OBJ_TMP_CC	:= \
	$(BASE_DIR)/src/teavpn2/net/linux/iface.o

OBJ_PRE_CC	+= $(OBJ_TMP_CC)

$(OBJ_TMP_CC):
	$(Q)echo "   CC		" "$(@:$(BASE_DIR)/%=%)"
	$(Q)$(CC) $(DEPFLAGS) $(CFLAGS) -c $(@:.o=.c) -o $(@)
