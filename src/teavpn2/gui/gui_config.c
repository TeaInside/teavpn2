// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021  Khaerul Ilham <khaerulilham163@gmail.com>
 * Copyright (C) 2021  Alviro Iskandar Setiawan <alviro.iskandar@gmail.com>
 */

#include <teavpn2/gui/gui.h>


static void btn_save_callback(GtkWidget *self, void *user_data)
{
	pr_notice("Save");
	(void) self;
	(void) user_data;
}

static void btn_save_as_callback(GtkWidget *self, void *user_data)
{
	pr_notice("Save As");
	(void) self;
	(void) user_data;
}

static void btn_cancel_callback(GtkWidget *self, void *user_data)
{
	pr_notice("Cancel");
	(void) self;
	(void) user_data;
}

void gui_config_create(struct gui *g)
{
	GtkBox *config = g->config;
	GtkBox *box_btn;
	GtkWidget *frame_conf, *scroller;
	GtkWidget *btn_cancel;
	const struct gui_callback callbacks[] = {
		GUI_CALLBACK(&g->config_btn_save, "clicked",
			     btn_save_callback, NULL),
		GUI_CALLBACK(&g->config_btn_save_as, "clicked",
			     btn_save_as_callback, NULL),
		GUI_CALLBACK(&btn_cancel, "clicked",
			     btn_cancel_callback, NULL),
	};


	box_btn = g_object_new(GTK_TYPE_BOX,
			       "orientation", GTK_ORIENTATION_HORIZONTAL,
			       "margin-top", 5,
			       "halign", GTK_ALIGN_CENTER,
			       "spacing", 5, NULL);
	g->config_btn_save = g_object_new(GTK_TYPE_BUTTON,
					  "label", "Save", NULL);
	g->config_btn_save_as = g_object_new(GTK_TYPE_BUTTON,
					     "label", "Save As", NULL);
	btn_cancel = g_object_new(GTK_TYPE_BUTTON,
				  "label", "Cancel", NULL);


	gtk_box_pack_start(box_btn, btn_cancel, FALSE, FALSE, 0);
	gtk_box_pack_start(box_btn, g->config_btn_save_as, FALSE, FALSE, 0);
	gtk_box_pack_start(box_btn, g->config_btn_save, FALSE, FALSE, 0);


	frame_conf = g_object_new(GTK_TYPE_FRAME,
				  "margin-bottom", 5,
				  "margin-start", 5,
				  "margin-end", 5, NULL);
	scroller = g_object_new(GTK_TYPE_SCROLLED_WINDOW,
				"parent", frame_conf, NULL);
	g_object_new(GTK_TYPE_LABEL,
		     "label", "Coming soon...",
		     "parent", scroller,
		     "vexpand", TRUE, NULL);

	gtk_box_pack_start(config, GTK_WIDGET(box_btn), FALSE, FALSE, 0);
	gtk_box_pack_start(config, frame_conf, TRUE, TRUE, 0);

	gui_utils_set_callback(callbacks, G_N_ELEMENTS(callbacks));

	gtk_widget_set_sensitive(GTK_WIDGET(g->config), FALSE);
}
