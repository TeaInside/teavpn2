
DEP_DIRS	+= $(BASE_DEP_DIR)/src/teavpn2/net

ifeq ($(UNAME_S),Linux)
	include $(BASE_DIR)/src/teavpn2/net/linux/Makefile
endif

OBJ_TMP_CC	:= \
	$(BASE_DIR)/src/teavpn2/net/iface.o

OBJ_PRE_CC	+= $(OBJ_TMP_CC)

$(OBJ_TMP_CC):
	@echo "   CC		" "$(@:$(BASE_DIR)/%=%)"
	@$(CC) $(DEPFLAGS) $(CFLAGS) -c $(@:.o=.c) -o $(@)
