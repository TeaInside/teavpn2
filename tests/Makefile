
include $(BASE_DIR)/tests/001_license/Makefile
include $(BASE_DIR)/tests/002_string/Makefile
include $(BASE_DIR)/tests/003_bc_arr/Makefile

export VG
export VGFLAGS

test:
	@+$(MAKE) --no-print-directory \
	&& $(MAKE) --no-print-directory __internal_do_test DO_TEST=1;

__internal_do_test: $(TESTS)


# 	@if [ $(DO_TEST) ]; then \
# 		$(BASE_DIR)/tests/do_test.sh $(TESTS); \
# 	else \
# 		echo "DO_TEST env is not set!"; \
# 		exit 1; \
# 	fi;

clean_test:
	@rm -vf $(TESTS)
