// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021  Khaerul Ilham <khaerulilham163@gmail.com>
 */

#include <teavpn2/gui/gui.h>

/* Private functions */
/* Callbacks */
static void _button_open_callback (GtkWidget *self, gpointer user_data);
static void _button_about_callback(GtkWidget *self, gpointer user_data);


/* Global (static) variables */
static GtkWidget *s_w_button_open;
static GtkWidget *s_w_button_about;


/* Public functions */
void gui_header_create(GtkWidget *parent)
{
	GtkWidget   *w_header;
	GuiCallback  callbacks[] = {
		{ &s_w_button_open , "clicked", _button_open_callback , NULL },
		{ &s_w_button_about, "clicked", _button_about_callback, NULL },
	};


	w_header         = gtk_header_bar_new();
	s_w_button_open  = gtk_button_new_from_icon_name("document-open",
							 GTK_ICON_SIZE_MENU);
	s_w_button_about = gtk_button_new_from_icon_name("help-about",
							 GTK_ICON_SIZE_MENU);

	gui_utils_set_callback(callbacks, G_N_ELEMENTS(callbacks));

	gtk_header_bar_set_show_close_button(GTK_HEADER_BAR(w_header), TRUE);
	gtk_header_bar_pack_start(GTK_HEADER_BAR(w_header), s_w_button_open);
	gtk_header_bar_pack_end(GTK_HEADER_BAR(w_header), s_w_button_about);

	gtk_window_set_titlebar(GTK_WINDOW(parent), w_header);
}


GtkWidget *gui_header_get_button_open(void)
{
	return s_w_button_open;
}


GtkWidget *gui_header_get_button_about(void)
{
	return s_w_button_about;
}


/* Private functions */
/* Callbacks */
static void _button_open_callback(GtkWidget *self, gpointer user_data)
{
	(void)self;
	(void)user_data;

	g_print("Open\n");
}


static void _button_about_callback(GtkWidget *self, gpointer user_data)
{
	(void)self;
	(void)user_data;

	g_print("About\n");
}
