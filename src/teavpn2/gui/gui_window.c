// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021  Khaerul Ilham <khaerulilham163@gmail.com>
 */

#include "gui.h"

typedef struct {
	GtkWidget *self;
	GtkWidget *label;
} _Notebook;


void gui_window_create(Gui *g)
{
	_Notebook notebook[] = {
		{
			gtk_box_new(GTK_ORIENTATION_VERTICAL, 5),
			gtk_label_new("Home")
		},
	};

	g->window.self  = gtk_application_window_new(g->self);
	g->window.child = gtk_notebook_new();

	for (guint i = 0; i < G_N_ELEMENTS(notebook); i++)
		gtk_notebook_append_page(GTK_NOTEBOOK(g->window.child),
					 notebook[i].self, notebook[i].label);

	gui_header_create(g->window.self);
	gui_home_create(notebook[0].self);
	gtk_window_set_title(GTK_WINDOW(g->window.self), GUI_WINDOW_TITLE);
	gtk_window_set_default_size(GTK_WINDOW(g->window.self), GUI_WINDOW_RES);
	gtk_window_set_focus(GTK_WINDOW(g->window.self),
			     gui_home_get_button_connect());
	gtk_window_set_resizable(GTK_WINDOW(g->window.self), FALSE);
	gtk_container_add(GTK_CONTAINER(g->window.self), g->window.child);
	gtk_widget_show_all(g->window.self);
}
