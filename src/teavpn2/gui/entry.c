// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021  Khaerul Ilham <khaerulilham163@gmail.com>
 */

#include "gui.h"

static void app_activate(GtkApplication *self, gpointer user_data)
{
	(void) self;
	gui_window_create((Gui *) user_data);
}


int gui_entry(int argc, char *argv[])
{
	int ret;
	Gui gui = {
		.self = gtk_application_new(GUI_ID, G_APPLICATION_FLAGS_NONE)
	};

	g_signal_connect(gui.self, "activate", G_CALLBACK(app_activate), &gui);
	ret = g_application_run(G_APPLICATION(gui.self), argc, argv);
	g_object_unref(gui.self);

	return ret;
}
