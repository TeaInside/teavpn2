// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021  Khaerul Ilham <khaerulilham163@gmail.com>
 */

#include <teavpn2/gui/gui.h>

/* Private functions */
static GtkWidget *_box_top_create(void);
static GtkWidget *_box_btm_create(void);

/* Callbacks */
static void _button_connect_callback(GtkWidget *self, gpointer user_data);


/* Global (static) variables */
static GtkWidget *s_w_label_path;
static GtkWidget *s_w_button_connect;
static GtkWidget *s_w_text_logger;
static GtkWidget *s_w_label_status;


/* Public functions */
void gui_home_create(GtkWidget *parent)
{
	gtk_box_pack_start(GTK_BOX(parent), _box_top_create(), FALSE, FALSE, 0);
	gtk_box_pack_end(GTK_BOX(parent), _box_btm_create(), TRUE, TRUE, 0);
}


GtkWidget *gui_home_get_label_path(void)
{
	return s_w_label_path;
}


GtkWidget *gui_home_get_button_connect(void)
{
	return s_w_button_connect;
}


GtkWidget *gui_home_get_text_logger(void)
{
	return s_w_text_logger;
}


GtkWidget *gui_home_get_label_status(void)
{
	return s_w_label_status;
}


/* Private functions */
static GtkWidget *_box_top_create(void)
{
	GtkWidget *box;
	GtkWidget *frame_conf;
	GuiCallback callbacks[] = {
		{ &s_w_button_connect, "clicked", _button_connect_callback, NULL },
	};

	box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
	s_w_button_connect = gtk_button_new_with_label("Connect");
	frame_conf = gtk_frame_new("Configuration File");
	s_w_label_path = gtk_label_new(GUI_DEFAULT_CONFIG);

	gui_utils_set_callback(callbacks, G_N_ELEMENTS(callbacks));

	gui_utils_set_margins(s_w_label_path, 5);
	gtk_widget_set_halign(s_w_button_connect, GTK_ALIGN_CENTER);
	gtk_widget_set_margin_top(s_w_button_connect, 5);

	gtk_container_add(GTK_CONTAINER(frame_conf), s_w_label_path);
	gtk_container_add(GTK_CONTAINER(box), frame_conf);
	gtk_container_add(GTK_CONTAINER(box), s_w_button_connect);
	gui_utils_set_margins(box, 5);

	return box;
}

static GtkWidget *_box_btm_create(void)
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


/* Callbacks */
static void _button_connect_callback(GtkWidget *self, gpointer user_data)
{
	(void) self;
	(void) user_data;

	g_print("Connect\n");
}
