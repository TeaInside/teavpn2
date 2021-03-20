
TESTS	+=	$(BASE_DIR)/tests/003_tcp_buf_queue/003_tcp_buf_queue.test__exec

$(BASE_DIR)/tests/003_tcp_buf_queue/003_tcp_buf_queue.test: $(BASE_DIR)/tests/003_tcp_buf_queue/003_tcp_buf_queue.c \
	$(TARGET_BIN) \
	$(OBJ_CC) \
	$(OBJ_PRE_CC)\
	$(BASE_DIR)/tests/003_tcp_buf_queue/003_tcp_buf_queue.c
	@echo "   CC		" "$(@:$(BASE_DIR)/%=%)"
	@$(CC) $(CFLAGS) $(BASE_DIR)/tests/003_tcp_buf_queue/003_tcp_buf_queue.c \
	-o $(@) $(OBJ_PRE_CC) $(OBJ_CC) $(TEST_LIB_LDFLAGS)


$(BASE_DIR)/tests/003_tcp_buf_queue/003_tcp_buf_queue.test__exec: $(BASE_DIR)/tests/003_tcp_buf_queue/003_tcp_buf_queue.test
	@$(BASE_DIR)/tests/003_tcp_buf_queue/003_tcp_buf_queue.test
