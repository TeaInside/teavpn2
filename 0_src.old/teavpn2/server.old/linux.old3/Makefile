#
# SPDX-License-Identifier: GPL-2.0
#
# @author Ammar Faizi <ammarfaizi2@gmail.com> https://www.facebook.com/ammarfaizi2
# @license GNU GPL-2.0
#
# Copyright (C) 2021  Ammar Faizi
#

DEP_DIRS += $(BASE_DEP_DIR)/src/teavpn2/server/linux


OBJ_TMP_CC := \
	$(BASE_DIR)/src/teavpn2/server/linux/tcp.o
# 	$(BASE_DIR)/src/teavpn2/server/linux/tcp_epoll.o



OBJ_JUST_RM += $(BASE_DIR)/src/teavpn2/server/linux/tcp_io_uring.o
ifdef IO_URING_SUPPORT
ifneq ($(IO_URING_SUPPORT),0)
	CFLAGS += -DIO_URING_SUPPORT=1
	OBJ_TMP_CC += $(BASE_DIR)/src/teavpn2/server/linux/tcp_io_uring.o
endif
endif


OBJ_PRE_CC += $(OBJ_TMP_CC)


$(OBJ_TMP_CC):
	$(CC_PRINT)
	$(Q)$(CC) $(PIC_FLAGS) $(DEPFLAGS) $(CFLAGS) -c $(O_TO_C) -o $(@)


$(BASE_DIR)/src/teavpn2/server/linux/tcp_io_uring.o: $(LIBURING_OBJ)
