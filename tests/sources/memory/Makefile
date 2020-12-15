
TEST_NAME       := memory

ifndef TEST_DIR
	$(error TEST_DIR is not set)
endif

ifndef TEST_BIN_DIR
	$(error TEST_BIN_DIR is not set)
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
DEP_FILES     := $(SRC_CC) $(SRC_CXX)
DEP_FILES     := $(DEP_FILES:$(BASE_DIR)/%=$(DEP_DIR)/%.d)
OBJ           := $(OBJ_CC) $(OBJ_CXX) $(GLOBAL_OBJ)

all: do_test

do_test: $(BIN_FILE)
	@bash $(SRC_DIR)/info.sh
	@$(VALGRIND) $(VALGRIND_FLAGS) $(BIN_FILE)

$(BIN_DIR):
	@mkdir -pv $(@)

$(BIN_FILE): $(OBJ_CC) $(OBJ_CXX) | $(BIN_DIR)
	$(LD) $(LDFLAGS) $(OBJ) -o $(@) $(LIB_LDFLAGS)

################# Compile test objects #################
$(DEP_DIRS):
	@mkdir -pv $(@)

$(OBJ_CC): $(MAKEFILE_LIST) | $(DEP_DIRS)
	$(CC) $(DEP_FLAGS) $(CFLAGS) -c $(@:%.o=%) -o $(@)

$(OBJ_CXX): $(MAKEFILE_LIST) | $(DEP_DIRS)
	$(CXX) $(DEP_FLAGS) $(CXXFLAGS) -c $(@:%.o=%) -o $(@)

-include $(DEP_FILES)
##########################################################

clean:
	@rm -rfv $(DEP_FILES) $(OBJ_CC) $(OBJ_CXX) $(BIN_FILE)
	@find -O2 $(SRC_DIR) \( -name '*.gcda' -o -name '*.gcno' \) | \
	xargs rm -vf
