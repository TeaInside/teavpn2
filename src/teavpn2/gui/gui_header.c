// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021  Khaerul Ilham <khaerulilham163@gmail.com>
 * Copyright (C) 2021  Alviro Iskandar Setiawan <alviro.iskandar@gmail.com>
 */

#include <teavpn2/gui/gui.h>


GtkWidget *s_w_button_open;
GtkWidget *s_w_button_about;


static void button_open_callback(GtkWidget *self, void *user_data)
{
	GtkWindow *parent = GTK_WINDOW(user_data);
	GtkFileChooserAction action = GTK_FILE_CHOOSER_ACTION_OPEN;
	char *file_name;
	GtkWidget *file_dialog;
	GtkFileChooser *file_chooser;
	GtkFileFilter *file_filter;

	file_filter = gtk_file_filter_new();
	file_dialog = gtk_file_chooser_dialog_new("Open Configuration File",
						  parent, action, "_Cancel",
						  GTK_RESPONSE_CANCEL, "_Open",
						  GTK_RESPONSE_ACCEPT, NULL);
	file_chooser = GTK_FILE_CHOOSER(file_dialog);

	gtk_file_filter_set_name(file_filter, "Configuration file");
	gtk_file_filter_add_pattern(file_filter, "*.ini");
	gtk_file_chooser_add_filter(file_chooser, file_filter);

	if (gtk_dialog_run(GTK_DIALOG(file_dialog)) == GTK_RESPONSE_ACCEPT) {
		file_name = gtk_file_chooser_get_filename(file_chooser);
		gtk_label_set_label(GTK_LABEL(gui_home_get_label_path()), file_name);
		g_free(file_name);
	}

	gtk_widget_destroy(file_dialog);
	(void) self;
}

static void button_about_callback(GtkWidget *self, void *user_data)
{
	gtk_show_about_dialog(GTK_WINDOW(user_data),
			      "program-name", GUI_PROGRAM_NAME,
			      "version", TEAVPN2_VERSION,
			      "license-type", GTK_LICENSE_GPL_2_0,
			      "website", "https://github.com/teainside/teavpn2",
			      NULL);
	(void) self;
}

void gui_header_create(GtkWidget *parent)
{
	GtkWidget *w_header;
	const struct gui_callback callbacks[] = {
		{
			.self		= &s_w_button_open,
			.signal_name	= "clicked",
			.func		= button_open_callback,
			.user_data	= parent
		},
		{
			.self		= &s_w_button_about,
			.signal_name	= "clicked",
			.func		= button_about_callback,
			.user_data	= parent
		},
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
