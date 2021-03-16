// SPDX-License-Identifier: GPL-2.0-only
/*
 *  teavpn2/include/lib/shell.h
 *
 *  Shell header for TeaVPN2
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#ifndef TEAVPN2__LIB__ARENA_H
#define TEAVPN2__LIB__ARENA_H

#include <stddef.h>


char *shell_exec(const char *cmd, char *buf, size_t buflen, size_t *outlen);

#endif /* #ifndef TEAVPN2__LIB__ARENA_H */
