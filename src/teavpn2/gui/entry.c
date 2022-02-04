// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021  Khaerul Ilham <khaerulilham163@gmail.com>
 * Copyright (C) 2021  Alviro Iskandar Setiawan <alviro.iskandar@gmail.com>
 */

#include <teavpn2/gui/gui.h>


static void app_startup(GtkApplication *self, void *user_data)
{
	struct gui *gui = (struct gui *) user_data;

	gui->app.txt_buffer_log = gtk_text_buffer_new(NULL);
	gui->app.cfg_file = g_string_new(GUI_DEFAULT_CONFIG);

	(void) self;
}

static void app_activate(GtkApplication *self, void *user_data)
{
	gui_window_create((struct gui *) user_data);

	(void) self;
}

static void app_shutdown(GtkApplication *self, void *user_data)
{
	g_string_free(((struct gui *) user_data)->app.cfg_file, TRUE);

	(void) self;
}

int gui_entry(int argc, char *argv[])
{
	int ret;
	struct gui gui;

	memset(&gui, 0, sizeof(struct gui));
	const struct gui_callback callbacks[] = {
		GUI_CALLBACK(&gui.app.self, "startup", app_startup, &gui),
		GUI_CALLBACK(&gui.app.self, "activate", app_activate, &gui),
		GUI_CALLBACK(&gui.app.self, "shutdown", app_shutdown, &gui),
	};


	gui.app.self = gtk_application_new(GUI_ID, G_APPLICATION_FLAGS_NONE);
	gdk_threads_add_timeout_full(G_PRIORITY_HIGH_IDLE, 100,
				     client_callback_event_loop, &gui, NULL);
	if ((ret = teavpn2_gui_event_init())) {
		g_object_unref(gui.app.self);
		return ret;
	}

	gui_pr_buffer_init(4096);
	gui_utils_set_callback(callbacks, G_N_ELEMENTS(callbacks));
	ret = g_application_run(G_APPLICATION(gui.app.self), argc, argv);
	g_object_unref(gui.app.self);
	teavpn2_gui_event_destroy();

	return ret;
}
