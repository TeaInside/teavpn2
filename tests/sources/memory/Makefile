
TEST_NAME       := memory

ifndef TEST_DIR
	$(error TEST_DIR is not set)
endif

SRC_DIR       := $(TEST_DIR)/sources/$(TEST_NAME)
BIN_DIR       := $(TEST_BIN_DIR)/$(TEST_NAME)
BIN_FILE      := $(BIN_DIR)/main
SRC_CC        := $(shell find ${SRC_DIR} -name '*.c')
SRC_CXX       := $(shell find ${SRC_DIR} -name '*.cpp')
OBJ_CC        := $(SRC_CC:%=%.o)
OBJ_CXX       := $(SRC_CXX:%=%.o)
DEP_FLAGS      = -MT $(@) -MMD -MP -MF $(DEP_DIR)/$(@:$(BASE_DIR)/%.o=%.d)
SRC_DIRL      := $(shell find ${SRC_DIR} -type d)
DEP_DIRS       = $(SRC_DIRL:$(BASE_DIR)/%=$(DEP_DIR)/%)

all: do_test

do_test: $(BIN_FILE)
	@bash $(SRC_DIR)/info.sh
	@$(VALGRIND) --show-leak-kinds=all $(BIN_FILE)

$(BIN_DIR):
	@mkdir -pv $(@)

$(BIN_FILE): $(OBJ_CC) $(GLOBAL_OBJ) | $(BIN_DIR)


$(DEP_DIRS):
	@mkdir -pv $(@)

$(OBJ_CC): $(DEP_DIRS)
	$(CC) $(DEP_FLAGS) $(CFLAGS) -c $(@:%.o=%) -o $(@)
