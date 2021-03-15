
TESTS	+=	$(BASE_DIR)/tests/001_license/001_license.test__exec

$(BASE_DIR)/tests/001_license/001_license.test: $(BASE_DIR)/tests/001_license/001_license.c \
	$(TARGET_BIN) \
	$(OBJ_CC) \
	$(OBJ_PRE_CC)\
	$(BASE_DIR)/tests/001_license/001_license.c
	@echo "   CC		" "$(@:$(BASE_DIR)/%=%)"
	@$(CC) $(CFLAGS) $(BASE_DIR)/tests/001_license/001_license.c \
	-o $(@) $(OBJ_PRE_CC) $(OBJ_CC) $(TEST_LIB_LDFLAGS)


$(BASE_DIR)/tests/001_license/001_license.test__exec: $(BASE_DIR)/tests/001_license/001_license.test
	@$(BASE_DIR)/tests/001_license/001_license.test
