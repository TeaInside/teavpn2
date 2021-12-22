// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021  Khaerul Ilham <khaerulilham163@gmail.com>
 */

#ifndef TEAVPN2__GUI_H
#define TEAVPN2__GUI_H

#define GUI_ID			"com.teainside.teavpn2"
#define GUI_PROGRAM_NAME	"TeaVPN2"
#define GUI_WINDOW_TITLE	"TeaVPN2 Client"
#define GUI_WINDOW_RES		500, 600

#define GUI_DEFAULT_CONFIG      "/etc/teavpn2/client.ini"

#include <gtk/gtk.h>
#include <teavpn2/common.h>


typedef struct {
	GtkApplication	*self;
	struct {
		GtkWidget	*self;
		GtkWidget	*child;
	} window;
} Gui;

typedef struct {
	GtkWidget	**self;
	const gchar	*signal_name;
	void		(*func)(GtkWidget *, gpointer);
	gpointer	user_data;
} GuiCallback;


/* gui_window.c */
void gui_window_create(Gui *g);

/* gui_header.c */
void gui_header_create(GtkWidget *parent);
GtkWidget *gui_header_get_button_open(void);
GtkWidget *gui_header_get_button_about(void);

/* gui_home.c */
void gui_home_create(GtkWidget *parent);
GtkWidget *gui_home_get_label_path(void);
GtkWidget *gui_home_get_button_connect(void);
GtkWidget *gui_home_get_text_logger(void);
GtkWidget *gui_home_get_label_status(void);

/* gui_config.c */
void gui_config_create(GtkWidget *parent);
GtkWidget *gui_config_get_button_save(void);
GtkWidget *gui_config_get_button_save_as(void);

/* gui_utils.c */
void gui_utils_set_callback(GuiCallback dest[], guint size);
void gui_utils_set_margins(GtkWidget *dest, gint size);

/* entry.c */
int gui_entry(int argc, char *argv[]);

#endif /* TEAVPN2__GUI_H */
