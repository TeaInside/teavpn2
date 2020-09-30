
ifndef TARGET_TEST
$(error TARGET_TEST is not set)
endif

SOURCES   = $(shell find ${TARGET_TEST} -name '*.c')
OBJECTS   = $(SOURCES:%=%.o)
TEST_FILE = $(BIN_DIR)/$(TARGET_TEST:sources/%=%).test


all: $(TEST_FILE)

$(OBJECTS): $(SOURCES)
	@echo "  CC @CFLAGS -c $(@:%.o=%) -o $(@)"
	@$(CC) $(CFLAGS) -c $(@:%.o=%) -o $@

$(TEST_FILE): $(OBJECTS) $(GLOBAL_OBJECTS)
	@echo "  LD @LDFLAGS @OBJECTS @GLOBAL_OBJECTS -o $(@) @LIB_LDFLAGS"
	$(CC) $(LDFLAGS) $(OBJECTS) $(GLOBAL_OBJECTS) -o $(TEST_FILE) $(LIB_LDFLAGS)

clean:
	rm -vf $(OBJECTS) $(TEST_FILE) || true