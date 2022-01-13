// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021  Khaerul Ilham <khaerulilham163@gmail.com>
 * Copyright (C) 2021  Alviro Iskandar Setiawan <alviro.iskandar@gmail.com>
 */

#include <teavpn2/gui/gui.h>

struct notebook {
	GtkWidget	*self;
	GtkWidget	*label;
};

void gui_window_create(struct gui *g)
{
	size_t i;
	struct notebook notebooks[] = {
		{
			gtk_box_new(GTK_ORIENTATION_VERTICAL, 5),
			gtk_label_new("Home")
		},
		{
			gtk_box_new(GTK_ORIENTATION_VERTICAL, 5),
			gtk_label_new("Configuration")
		}
	};
	const size_t nr_notebook = sizeof(notebooks) / sizeof(*notebooks);

	g->window.self  = gtk_application_window_new(g->self);
	g->window.child = gtk_notebook_new();

	for (i = 0; i < nr_notebook; i++)
		gtk_notebook_append_page(GTK_NOTEBOOK(g->window.child),
					 notebooks[i].self, notebooks[i].label);

	gtk_application_add_window(g->self, GTK_WINDOW(g->window.self));
	gui_header_create(g->window.self);
	gui_home_create(notebooks[0].self);
	gui_config_create(notebooks[1].self);
	gtk_window_set_title(GTK_WINDOW(g->window.self), GUI_WINDOW_TITLE);
	gtk_window_set_default_size(GTK_WINDOW(g->window.self), GUI_WINDOW_RES);
	gtk_window_set_focus(GTK_WINDOW(g->window.self),
			     gui_home_get_button_connect());
	gtk_window_set_resizable(GTK_WINDOW(g->window.self), FALSE);
	gtk_container_add(GTK_CONTAINER(g->window.self), g->window.child);
	gtk_widget_show_all(g->window.self);
}
