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
				 NULL);

	g->window_notebook = gtk_notebook_new();
	g->home = GTK_BOX(gtk_box_new(GTK_ORIENTATION_VERTICAL, 5));
	g->config = GTK_BOX(gtk_box_new(GTK_ORIENTATION_VERTICAL, 5));
	gtk_notebook_append_page(GTK_NOTEBOOK(g->window_notebook),
				 GTK_WIDGET(g->home), gtk_label_new("Home"));
	gtk_notebook_append_page(GTK_NOTEBOOK(g->window_notebook),
				 GTK_WIDGET(g->config), gtk_label_new("Configuration"));

	gui_header_create(g);
	gui_home_create(g);
	gui_config_create(g);

	gtk_window_set_focus(g->window, g->home_btn_connect);
	gtk_window_set_resizable(g->window, FALSE);
	gtk_container_add(GTK_CONTAINER(g->window), g->window_notebook);
	gtk_widget_show_all(GTK_WIDGET(g->window));
}
