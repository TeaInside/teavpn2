#
# SPDX-License-Identifier: GPL-2.0-only
#
# @author Ammar Faizi <ammarfaizi2@gmail.com> https://www.facebook.com/ammarfaizi2
# @license GNU GPL-2.0-only
#
# Build printing construction.
#

#
# Verbose option
#
# `make V=1` will show the full commands
#
ifndef V
	V := 0
endif


ifeq ($(V),0)
	Q := @
	S := @
else
	Q :=
	S := @\#
endif


MKDIR_PRINT	= $(S)echo "   MKDIR	" "$(@:$(BASE_DIR)/%=%)"
CC_PRINT	= $(S)echo "   CC		" "$(@:$(BASE_DIR)/%=%)"
LD_PRINT	= $(S)echo "   LD		" "$(@)"
