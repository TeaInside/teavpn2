// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021  Khaerul Ilham <khaerulilham163@gmail.com>
 */

#include "gui.h"

/* Private functions */
static GtkWidget *_button_connect_create(const gchar *label);
static GtkWidget *_text_log_create(GtkWidget **text_view);

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
	GtkWidget *w_box_top, *w_box_btm;
	GuiCallback callbacks[] = {
		{ &s_w_button_connect, "clicked", _button_connect_callback, NULL },
	};


	w_box_top          = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
	w_box_btm          = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
	s_w_label_path     = gtk_label_new("Configuration file: /home/x/x.ini");
	s_w_button_connect = _button_connect_create("Connect");
	s_w_label_status   = gtk_label_new("Disconnected");

	gui_utils_set_callback(callbacks, G_N_ELEMENTS(callbacks));

	/* w_box_top */
	gtk_box_pack_start(GTK_BOX(w_box_top), s_w_label_path, FALSE, FALSE, 0);
	gtk_box_pack_start(GTK_BOX(w_box_top), s_w_button_connect, FALSE, FALSE,
			   0);
	gtk_box_set_homogeneous(GTK_BOX(w_box_top), TRUE);
	gui_utils_set_margins(w_box_top, 5);

	/* w_box_btm */
	gtk_box_pack_start(GTK_BOX(w_box_btm),
			   _text_log_create(&s_w_text_logger), TRUE, TRUE, 0);
	gtk_box_pack_start(GTK_BOX(w_box_btm), s_w_label_status, FALSE, FALSE,
			   0);
	gui_utils_set_margins(w_box_btm, 5);

	/* parent */
	gtk_box_pack_start(GTK_BOX(parent), w_box_top, FALSE, FALSE, 0);
	gtk_box_pack_end(GTK_BOX(parent), w_box_btm, TRUE, TRUE, 0);
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
static GtkWidget *_button_connect_create(const gchar *label)
{
	GtkWidget *button = gtk_button_new_with_label(label);

	gtk_widget_set_halign(button, GTK_ALIGN_CENTER);

	return button;
}


static GtkWidget *_text_log_create(GtkWidget **text_view)
{
	GtkWidget *frame, *scroller;

	frame      = gtk_frame_new("Logs:");
	scroller   = gtk_scrolled_window_new(NULL, NULL);
	*text_view = gtk_text_view_new();

	gtk_text_view_set_editable(GTK_TEXT_VIEW(*text_view), FALSE);
	gtk_widget_set_vexpand(*text_view, TRUE);
	gtk_container_add(GTK_CONTAINER(scroller), *text_view);
	gtk_container_add(GTK_CONTAINER(frame), scroller);
	return frame;
}


/* Callbacks */
static void _button_connect_callback(GtkWidget *self, gpointer user_data)
{
	(void) self;
	(void) user_data;
	g_print("Connect\n");
}
