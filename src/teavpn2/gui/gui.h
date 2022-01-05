// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021  Khaerul Ilham <khaerulilham163@gmail.com>
 * Copyright (C) 2021  Alviro Iskandar Setiawan <alviro.iskandar@gmail.com>
 */

#ifndef TEAVPN2__GUI__GUI_H
#define TEAVPN2__GUI__GUI_H

#ifdef CONFIG_GUI
#include <gtk/gtk.h>
#else
typedef struct GtkWidget GtkWidget;
typedef struct GtkApplication GtkApplication;
#endif

#include <teavpn2/common.h>
#include <teavpn2/gui/events.h>

#define GUI_ID			"com.teainside.teavpn2"
#define GUI_PROGRAM_NAME	"TeaVPN2"
#define GUI_WINDOW_TITLE	"TeaVPN2 Client"
#define GUI_WINDOW_RES		500, 600
#define GUI_DEFAULT_CONFIG	"/etc/teavpn2/client.ini"

struct gui {
	GtkApplication		*self;
	struct {
		GtkWidget	*self;
		GtkWidget	*child;
	} window;
};

struct gui_callback {
	GtkWidget		**self;
	const char		*signal_name;
	void			(*func)(GtkWidget *widget, void *data);
	void			*user_data;
};


/* entry.c */
extern int gui_entry(int argc, char *argv[]);


/* gui_window.c */
extern void gui_window_create(struct gui *g);


/* gui_header.c */
extern GtkWidget *s_w_button_open;
extern GtkWidget *s_w_button_about;
extern void gui_header_create(GtkWidget *parent);

static inline GtkWidget *gui_header_get_button_open(void)
{
	return s_w_button_open;
}

static inline GtkWidget *gui_header_get_button_about(void)
{
	return s_w_button_about;
}


/* gui_home.c */
extern GtkWidget *s_w_label_path;
extern GtkWidget *s_w_button_connect;
extern GtkWidget *s_w_text_logger;
extern GtkWidget *s_w_label_status;
extern void gui_home_insert_text_logger(const char *msg);
extern void gui_home_create(GtkWidget *parent);

static inline GtkWidget *gui_home_get_label_path(void)
{
	return s_w_label_path;
}

static inline GtkWidget *gui_home_get_button_connect(void)
{
	return s_w_button_connect;
}

static inline GtkWidget *gui_home_get_text_logger(void)
{
	return s_w_text_logger;
}

static inline GtkWidget *gui_home_get_label_status(void)
{
	return s_w_label_status;
}


/* gui_utils.c */
extern void gui_utils_set_callback(const struct gui_callback *dest, size_t size);
extern void gui_utils_set_margins(GtkWidget *dest, int size);


/* gui_config.c */
extern GtkWidget *s_w_button_save;
extern GtkWidget *s_w_button_save_as;
extern void gui_config_create(GtkWidget *parent);

static inline GtkWidget *gui_config_get_button_save(void)
{
	return s_w_button_save;
}

static inline GtkWidget *gui_config_get_button_save_as(void)
{
	return s_w_button_save_as;
}

#endif /* #ifndef #ifndef TEAVPN2__GUI__GUI_H */
