
TESTS	+=	$(BASE_DIR)/tests/002_string/002_string.test

$(BASE_DIR)/tests/002_string/002_string.test: \
	$(TARGET_BIN) \
	$(OBJ_CC) \
	$(OBJ_PRE_CC)\
	$(BASE_DIR)/tests/002_string/002_string.c
	@echo "   CC		" "$(@:$(BASE_DIR)/%=%)"
	@$(CC) $(CFLAGS) $(BASE_DIR)/tests/002_string/002_string.c \
	-o $(@) $(OBJ_PRE_CC) $(OBJ_CC) $(TEST_LIB_LDFLAGS)
