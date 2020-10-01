
ifndef TARGET_TEST
$(error TARGET_TEST is not set)
endif

SOURCES   = $(shell find ${TARGET_TEST} -name '*.c')
OBJECTS   = $(SOURCES:%=%.o)
TEST_FILE = $(BIN_DIR)/$(TARGET_TEST:sources/%=%).test

TEST_DEPDIR    = $(TARGET_TEST:%=${ROOT_DEPDIR}/%)
TEST_DEPFLAGS  = -MT $@ -MMD -MP -MF ${ROOT_DEPDIR}/$*.d
TEST_DEPFILES  = $(SOURCES:%=${ROOT_DEPDIR}/%.d)

all: $(TEST_FILE)

$(ROOT_DEPDIR):
	mkdir -pv ${@}

$(TEST_DEPDIR): | $(ROOT_DEPDIR)
	mkdir -pv ${@}

$(OBJECTS): $(MAKEFILE_DEPS) | $(TEST_DEPDIR)
	echo "  CC @CFLAGS -c $(@:%.o=%) -o $(@)"
	$(CC) $(TEST_DEPFLAGS) $(CFLAGS) -c $(@:%.o=%) -o $@

$(TEST_FILE): $(MAKEFILE_DEPS) $(OBJECTS) $(GLOBAL_OBJECTS)
	echo "  LD @LDFLAGS @OBJECTS @GLOBAL_OBJECTS -o $(@) @LIB_LDFLAGS"
	$(CC) $(LDFLAGS) $(OBJECTS) $(GLOBAL_OBJECTS) -o $(TEST_FILE) $(LIB_LDFLAGS)

-include $(TEST_DEPFILES)

clean:
	rm -vfr $(TEST_DEPDIR) $(OBJECTS) $(TEST_FILE) || true
