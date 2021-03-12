
TESTS	+=	$(BASE_DIR)/tests/001_license/001_license.test

$(BASE_DIR)/tests/001_license/001_license.test: \
	$(TARGET_BIN) \
	$(OBJ_CC) \
	$(OBJ_PRE_CC)\
	$(BASE_DIR)/tests/001_license/001_license.c
	@echo "   CC		" "$(@:$(BASE_DIR)/%=%)"
	@$(CC) $(CFLAGS) $(BASE_DIR)/tests/001_license/001_license.c \
	-o $(@) $(OBJ_PRE_CC) $(OBJ_CC) $(TEST_LIB_LDFLAGS)
