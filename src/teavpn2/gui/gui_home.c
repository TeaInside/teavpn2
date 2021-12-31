// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021  Khaerul Ilham <khaerulilham163@gmail.com>
 * Copyright (C) 2021  Alviro Iskandar Setiawan <alviro.iskandar@gmail.com>
 */

#include <teavpn2/gui/gui.h>

GtkWidget *s_w_label_path;
GtkWidget *s_w_button_connect;
GtkWidget *s_w_text_logger;
GtkWidget *s_w_label_status;


static void button_connect_callback(GtkWidget *self, void *user_data)
{
	(void) self;
	(void) user_data;
	g_print("Connect\n");
}

static GtkWidget *box_top_create(void)
{
	GtkWidget *box;
	GtkWidget *frame_conf;
	static const struct gui_callback callbacks[] = {
		{
			.self		= &s_w_button_connect,
			.signal_name	= "clicked",
			.func		= button_connect_callback,
			.user_data	= NULL
		},
	};
	const size_t nr_callbacks = sizeof(callbacks) / sizeof(*callbacks);

	box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
	s_w_button_connect = gtk_button_new_with_label("Connect");
	frame_conf = gtk_frame_new("Configuration File");
	s_w_label_path = gtk_label_new(GUI_DEFAULT_CONFIG);

	gui_utils_set_callback(callbacks, nr_callbacks);

	gui_utils_set_margins(s_w_label_path, 5);
	gtk_widget_set_halign(s_w_button_connect, GTK_ALIGN_CENTER);
	gtk_widget_set_margin_top(s_w_button_connect, 5);

	gtk_container_add(GTK_CONTAINER(frame_conf), s_w_label_path);
	gtk_container_add(GTK_CONTAINER(box), frame_conf);
	gtk_container_add(GTK_CONTAINER(box), s_w_button_connect);
	gui_utils_set_margins(box, 5);

	return box;
}

static GtkWidget *box_btm_create(void)
{
	GtkWidget *box;
	GtkWidget *frame_log, *scroller;

	box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
	frame_log = gtk_frame_new("Log:");
	scroller = gtk_scrolled_window_new(NULL, NULL);
	s_w_text_logger = gtk_text_view_new();

	gtk_text_view_set_editable(GTK_TEXT_VIEW(s_w_text_logger), FALSE);
	gtk_widget_set_vexpand(s_w_text_logger, TRUE);
	gtk_container_add(GTK_CONTAINER(scroller), s_w_text_logger);
	gtk_container_add(GTK_CONTAINER(frame_log), scroller);
	gtk_container_add(GTK_CONTAINER(box), frame_log);
	gui_utils_set_margins(frame_log, 5);

	return box;
}

void gui_home_create(GtkWidget *parent)
{
	gtk_box_pack_start(GTK_BOX(parent), box_top_create(), FALSE, FALSE, 0);
	gtk_box_pack_end(GTK_BOX(parent), box_btm_create(), TRUE, TRUE, 0);
}
