// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021  Khaerul Ilham <khaerulilham163@gmail.com>
 * Copyright (C) 2021  Alviro Iskandar Setiawan <alviro.iskandar@gmail.com>
 */

#ifndef TEAVPN2__GUI__GUI_H
#define TEAVPN2__GUI__GUI_H

#ifdef CONFIG_GUI
#include <gtk/gtk.h>
#endif

#include <teavpn2/common.h>
#include <teavpn2/client/common.h>
#include <teavpn2/gui/events.h>

#define GUI_ID			"com.teainside.teavpn2"
#define GUI_PROGRAM_NAME	"TeaVPN2"
#define GUI_WINDOW_TITLE	"TeaVPN2 Client"
#define GUI_WINDOW_WIDTH	500
#define GUI_WINDOW_HEIGHT	600
#define GUI_DEFAULT_CONFIG	"/etc/teavpn2/client.ini"

#define GUI_CALLBACK(SF, SG, FC, DT)\
{ .instance = (void **)SF, .signal = SG, .func = G_CALLBACK(FC), .data = DT }


struct app;
struct gui;
struct gui_callback;

#ifdef CONFIG_GUI
struct app {
	GtkApplication	*self;

	GtkTextBuffer	*txt_buffer_log;
	GString		*cfg_file;
	struct cli_cfg	cli_cfg;
};

struct gui {
	struct app	app;

	/* window */
	GtkWindow	*window;
	GtkWidget	*window_notebook;

	/* header */
	GtkHeaderBar	*header;
	GtkWidget	*header_btn_open;
	GtkWidget	*header_btn_about;

	/* home */
	GtkBox		*home;
	GtkWidget	*home_lbl_path;
	GtkWidget	*home_btn_connect;
	GtkWidget	*home_txt_logger;
	GtkWidget	*home_lbl_status;

	/* config */
	GtkBox		*config;
	GtkWidget	*config_btn_save;
	GtkWidget	*config_btn_save_as;

	/* */
};

struct gui_callback {
	void		**instance;
	const char	*signal;
	void		(*func)(void);
	void		*data;
};
#endif /* #ifdef CONFIG_GUI */


/* entry.c */
extern int gui_entry(int argc, char *argv[]);


/* gui_window.c */
extern void gui_window_create(struct gui *g);


/* gui_header.c */
extern void gui_header_create(struct gui *g);


/* gui_home.c */
extern void gui_home_create(struct gui *g);
extern void gui_home_insert_txt_logger(struct gui *g, const char *msg);


/* gui_config.c */
extern void gui_config_create(struct gui *g);


/* gui_utils.c */
extern void gui_utils_set_callback(const struct gui_callback *dest, size_t size);

#endif /* #ifndef #ifndef TEAVPN2__GUI__GUI_H */
