// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021  Khaerul Ilham <khaerulilham163@gmail.com>
 * Copyright (C) 2021  Alviro Iskandar Setiawan <alviro.iskandar@gmail.com>
 */

#include <teavpn2/gui/gui.h>


static void btn_open_callback(GtkWidget *self, void *user_data)
{
	struct gui *gui = (struct gui *) user_data;
	GtkFileChooserAction action = GTK_FILE_CHOOSER_ACTION_OPEN;
	char *file_name;
	GtkWidget *file_dialog;
	GtkFileChooser *file_chooser;
	GtkFileFilter *file_filter;

	file_filter = gtk_file_filter_new();
	file_dialog = gtk_file_chooser_dialog_new("Open Configuration File",
						  gui->window, action, "_Cancel",
						  GTK_RESPONSE_CANCEL, "_Open",
						  GTK_RESPONSE_ACCEPT, NULL);
	file_chooser = GTK_FILE_CHOOSER(file_dialog);

	gtk_file_filter_set_name(file_filter, "Configuration file");
	gtk_file_filter_add_pattern(file_filter, "*.ini");
	gtk_file_chooser_add_filter(file_chooser, file_filter);

	if (gtk_dialog_run(GTK_DIALOG(file_dialog)) == GTK_RESPONSE_ACCEPT) {
		file_name = gtk_file_chooser_get_filename(file_chooser);
		g_string_assign(gui->app.cfg_file, file_name);
		gtk_label_set_label(GTK_LABEL(gui->home_lbl_path),
				    gui->app.cfg_file->str);
		g_free(file_name);
	}

	gtk_widget_destroy(file_dialog);
	(void) self;
}

static void btn_about_callback(GtkWidget *self, void *user_data)
{
	gtk_show_about_dialog(GTK_WINDOW(user_data),
			      "program-name", GUI_PROGRAM_NAME,
			      "version", TEAVPN2_VERSION,
			      "license-type", GTK_LICENSE_GPL_2_0,
			      "website", "https://github.com/teainside/teavpn2",
			      NULL);
	(void) self;
}

void gui_header_create(struct gui *g)
{
	const struct gui_callback callbacks[] = {
		GUI_CALLBACK(&g->header_btn_open, "clicked",
			     btn_open_callback, g),
		GUI_CALLBACK(&g->header_btn_about, "clicked",
			     btn_about_callback, g->window),
	};


	g->header = g_object_new(GTK_TYPE_HEADER_BAR,
				 "title", GUI_WINDOW_TITLE,
				 "show-close-button", TRUE, NULL);
	g->header_btn_open = gtk_button_new_from_icon_name("document-open",
							 GTK_ICON_SIZE_MENU);
	g->header_btn_about = gtk_button_new_from_icon_name("help-about",
							 GTK_ICON_SIZE_MENU);


	gtk_header_bar_pack_start(g->header, g->header_btn_open);
	gtk_header_bar_pack_end(g->header, g->header_btn_about);
	gtk_window_set_titlebar(g->window, GTK_WIDGET(g->header));

	gui_utils_set_callback(callbacks, G_N_ELEMENTS(callbacks));
}
