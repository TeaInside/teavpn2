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
	g->window.self  = gtk_application_window_new(g->self);
	g->window.child = gtk_notebook_new();

	gui_header_create(g->window.self);
	gtk_window_set_title(GTK_WINDOW(g->window.self), GUI_WINDOW_TITLE);
	gtk_window_set_default_size(GTK_WINDOW(g->window.self), GUI_WINDOW_RES);

	gtk_window_set_resizable(GTK_WINDOW(g->window.self), FALSE);
	gtk_container_add(GTK_CONTAINER(g->window.self), g->window.child);
	gtk_widget_show_all(g->window.self);
}
