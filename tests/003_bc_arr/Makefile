
TESTS	+=	$(BASE_DIR)/tests/003_bc_arr/003_bc_arr.test__exec

$(BASE_DIR)/tests/003_bc_arr/003_bc_arr.test: $(BASE_DIR)/tests/003_bc_arr/003_bc_arr.c \
	$(TARGET_BIN) \
	$(OBJ_CC) \
	$(OBJ_PRE_CC)\
	$(BASE_DIR)/tests/003_bc_arr/003_bc_arr.c
	@echo "   CC		" "$(@:$(BASE_DIR)/%=%)"
	@$(CC) $(CFLAGS) $(BASE_DIR)/tests/003_bc_arr/003_bc_arr.c \
	-o $(@) $(OBJ_PRE_CC) $(OBJ_CC) $(TEST_LIB_LDFLAGS)


$(BASE_DIR)/tests/003_bc_arr/003_bc_arr.test__exec: $(BASE_DIR)/tests/003_bc_arr/003_bc_arr.test
	@$(BASE_DIR)/tests/003_bc_arr/003_bc_arr.test
