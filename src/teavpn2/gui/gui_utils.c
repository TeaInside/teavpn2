// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021  Khaerul Ilham <khaerulilham163@gmail.com>
 * Copyright (C) 2021  Alviro Iskandar Setiawan <alviro.iskandar@gmail.com>
 */

#include <teavpn2/gui/gui.h>

void gui_utils_set_callback(const struct gui_callback *dest, size_t size)
{
	size_t i;

	for (i = 0; i < size; i++)
		g_signal_connect(*dest[i].self, dest[i].signal_name,
				 G_CALLBACK(dest[i].func), dest[i].user_data);
}

/* Probably we should add option flags instead of sets all of them */
void gui_utils_set_margins(GtkWidget *dest, int size)
{
	gtk_widget_set_margin_start(dest, size);
	gtk_widget_set_margin_end(dest, size);
	gtk_widget_set_margin_top(dest, size);
	gtk_widget_set_margin_bottom(dest, size);
}
