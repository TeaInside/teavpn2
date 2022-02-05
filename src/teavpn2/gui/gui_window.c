// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021  Khaerul Ilham <khaerulilham163@gmail.com>
 * Copyright (C) 2021  Alviro Iskandar Setiawan <alviro.iskandar@gmail.com>
 */

#include <teavpn2/gui/gui.h>


void gui_window_create(struct gui *g)
{
	g->window = g_object_new(GTK_TYPE_WINDOW,
				 "application", g->app.self,
				 "default-width", GUI_WINDOW_WIDTH,
				 "default-height", GUI_WINDOW_HEIGHT,
				 "resizable", FALSE,
				 NULL);
	g->window_notebook = g_object_new(GTK_TYPE_NOTEBOOK,
					  "parent", g->window, NULL);
	g->home = g_object_new(GTK_TYPE_BOX,
			       "orientation", GTK_ORIENTATION_VERTICAL,
			       "spacing", 5, NULL);
	g->config = g_object_new(GTK_TYPE_BOX,
				 "orientation", GTK_ORIENTATION_VERTICAL,
				 "spacing", 5, NULL);

	gtk_notebook_append_page(GTK_NOTEBOOK(g->window_notebook),
				 GTK_WIDGET(g->home), gtk_label_new("Home"));
	gtk_notebook_append_page(GTK_NOTEBOOK(g->window_notebook),
				 GTK_WIDGET(g->config), gtk_label_new("Configuration"));

	gui_header_create(g);
	gui_home_create(g);
	gui_config_create(g);

	gtk_window_set_focus(g->window, g->home_btn_connect);
	gtk_widget_show_all(GTK_WIDGET(g->window));
}
