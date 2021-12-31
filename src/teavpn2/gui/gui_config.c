// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021  Khaerul Ilham <khaerulilham163@gmail.com>
 * Copyright (C) 2021  Alviro Iskandar Setiawan <alviro.iskandar@gmail.com>
 */

#include <teavpn2/gui/gui.h>

GtkWidget *s_w_button_save;
GtkWidget *s_w_button_save_as;

static void btn_save_callback(GtkWidget *self, gpointer user_data)
{
	pr_notice("Save");
	(void) self;
	(void) user_data;
}

static void btn_save_as_callback(GtkWidget *self, gpointer user_data)
{
	pr_notice("Save As");
	(void) self;
	(void) user_data;
}

static void btn_cancel_callback(GtkWidget *self, gpointer user_data)
{
	pr_notice("Cancel");
	(void) self;
	(void) user_data;
}

void gui_config_create(GtkWidget *parent)
{
	GtkWidget *w_box_top, *w_box_btm, *w_frame_btm, *w_scroller,
		  *w_button_cancel, *w_label_test;

	const struct gui_callback callbacks[] = {
		{
			.self		= &s_w_button_save,
			.signal_name	= "clicked",
			.func		= btn_save_callback,
			.user_data	= NULL
		},
		{
			.self		= &s_w_button_save_as,
			.signal_name	= "clicked",
			.func		= btn_save_as_callback,
			.user_data	= NULL
		},
		{
			.self		= &w_button_cancel,
			.signal_name	= "clicked",
			.func		= btn_cancel_callback,
			.user_data	= NULL
		},
	};


	w_box_top          = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
	w_box_btm          = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
	w_frame_btm        = gtk_frame_new(NULL);
	w_scroller         = gtk_scrolled_window_new(NULL, NULL);
	s_w_button_save    = gtk_button_new_with_label("Save");
	s_w_button_save_as = gtk_button_new_with_label("Save As");
	w_button_cancel    = gtk_button_new_with_label("Cancel");
	w_label_test       = gtk_label_new("Coming soon...");

	gui_utils_set_callback(callbacks, G_N_ELEMENTS(callbacks));

	/* w_box_top */
	gtk_box_pack_start(GTK_BOX(w_box_top), w_button_cancel, FALSE, FALSE, 0);
	gtk_box_pack_start(GTK_BOX(w_box_top), s_w_button_save, FALSE, FALSE, 0);
	gtk_box_pack_start(GTK_BOX(w_box_top), s_w_button_save_as, FALSE, FALSE,
			   0);
	gtk_widget_set_halign(w_box_top, GTK_ALIGN_CENTER);
	gui_utils_set_margins(w_box_top, 5);

	/* w_box_btm */
	gtk_box_pack_start(GTK_BOX(w_box_btm), w_label_test, TRUE, TRUE, 0);

	gtk_widget_set_vexpand(w_label_test, TRUE); /* Test */
	gtk_container_add(GTK_CONTAINER(w_scroller), w_box_btm);
	gtk_container_add(GTK_CONTAINER(w_frame_btm), w_scroller);
	gui_utils_set_margins(w_frame_btm, 5);

	/* parent */
	gtk_box_pack_start(GTK_BOX(parent), w_box_top, FALSE, FALSE, 0);
	gtk_box_pack_start(GTK_BOX(parent), w_frame_btm, TRUE, TRUE, 0);
}
