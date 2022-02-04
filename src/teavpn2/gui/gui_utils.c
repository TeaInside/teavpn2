// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021  Khaerul Ilham <khaerulilham163@gmail.com>
 * Copyright (C) 2021  Alviro Iskandar Setiawan <alviro.iskandar@gmail.com>
 */

#include <teavpn2/gui/gui.h>

void gui_utils_set_callback(const struct gui_callback *dest, size_t size)
{
	do {
		size--;
		g_signal_connect(*dest[size].instance, dest[size].signal,
				 dest[size].func, dest[size].data);
	} while (size > 0);
}

