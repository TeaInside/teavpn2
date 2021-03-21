
TESTS	+=	$(BASE_DIR)/tests/004_tcp_slot_stack/004_tcp_slot_stack.test__exec

$(BASE_DIR)/tests/004_tcp_slot_stack/004_tcp_slot_stack.test: $(BASE_DIR)/tests/004_tcp_slot_stack/004_tcp_slot_stack.c \
	$(TARGET_BIN) \
	$(OBJ_CC) \
	$(OBJ_PRE_CC)\
	$(BASE_DIR)/tests/004_tcp_slot_stack/004_tcp_slot_stack.c
	@echo "   CC		" "$(@:$(BASE_DIR)/%=%)"
	@$(CC) $(CFLAGS) $(BASE_DIR)/tests/004_tcp_slot_stack/004_tcp_slot_stack.c \
	-o $(@) $(OBJ_PRE_CC) $(OBJ_CC) $(TEST_LIB_LDFLAGS)


$(BASE_DIR)/tests/004_tcp_slot_stack/004_tcp_slot_stack.test__exec: $(BASE_DIR)/tests/004_tcp_slot_stack/004_tcp_slot_stack.test
	@$(BASE_DIR)/tests/004_tcp_slot_stack/004_tcp_slot_stack.test
