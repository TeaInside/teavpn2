# SPDX-License-Identifier: GPL-2.0
#
# @author Ammar Faizi <ammarfaizi2@gmail.com> https://www.facebook.com/ammarfaizi2
# @license GNU GPL-v2
#
# TeaVPN2 - Fast and Free VPN Software
#

INCLUDE_DIR += -I$(BASE_DIR)/src/ext/criterion/include
DEP_DIRS	+= $(BASE_DEP_DIR)/src/ext/criterion

ifeq ($(DO_TEST),1)
	TEST_LIB_LDFLAGS = -L$(BASE_DIR)/src/ext/criterion/lib -lcriterion $(LIB_LDFLAGS)
	LD_LIBRARY_PATH=$(BASE_DIR)/src/ext/criterion/lib
	LD_PRELOAD=$(BASE_DIR)/src/ext/criterion/lib/libcriterion.so.3.1.0
	export LD_PRELOAD
	export LD_LIBRARY_PATH
endif
