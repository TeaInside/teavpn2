#
# SPDX-License-Identifier: GPL-2.0
#
# @author Ammar Faizi <ammarfaizi2@gmail.com> https://www.facebook.com/ammarfaizi2
# @license GNU GPL-v2
#
# <Project Name> - <Short Description>
#

VERSION	= 0
PATCHLEVEL = 0
SUBLEVEL = 1
EXTRAVERSION = -rc1
NAME = Blue Tea
TARGET_BIN = 
PACKAGE_NAME = teavpn2-$(VERSION).$(PATCHLEVEL).$(SUBLEVEL)$(EXTRAVERSION)

CC 	:= cc
CXX	:= c++
LD	:= $(CXX)
VG	:= valgrind

RM	:= rm
MKDIR	:= mkdir
STRIP	:= strip


#############################################################################
#
# __As a rule of thumb__
# Don't change below this line expect you really know what you're doing.
#
#############################################################################
BASE_DIR	:= $(dir $(realpath $(lastword $(MAKEFILE_LIST))))
BASE_DIR	:= $(strip $(patsubst %/, %, $(BASE_DIR)))
BASE_DEP_DIR	:= $(BASE_DIR)/.deps
MAKEFILE_FILE	:= $(lastword $(MAKEFILE_LIST))
