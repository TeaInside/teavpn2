// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021  Khaerul Ilham <khaerulilham163@gmail.com>
 * Copyright (C) 2021  Alviro Iskandar Setiawan <alviro.iskandar@gmail.com>
 */

#include <teavpn2/gui/gui.h>

static void app_activate(GtkApplication *self, void *user_data)
{
	struct gui *gui = user_data;

	gui_window_create(gui);
	(void) self;
}

int gui_entry(int argc, char *argv[])
{
	int ret;
	struct gui gui = {
		.self = gtk_application_new(GUI_ID, G_APPLICATION_FLAGS_NONE)
	};

	gdk_threads_add_timeout_full(G_PRIORITY_HIGH_IDLE, 100,
				     client_callback_event_loop, &gui, NULL);
	ret = teavpn2_gui_event_init(&gui);
	if (ret) {
		g_object_unref(gui.self);
		return ret;
	}

	gui_pr_buffer_init(4096);
	g_signal_connect(gui.self, "activate", G_CALLBACK(app_activate), &gui);
	ret = g_application_run(G_APPLICATION(gui.self), argc, argv);
	g_object_unref(gui.self);
	teavpn2_gui_event_destroy();

	return ret;
}
