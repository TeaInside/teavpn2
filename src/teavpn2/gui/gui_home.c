// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021  Khaerul Ilham <khaerulilham163@gmail.com>
 * Copyright (C) 2021  Alviro Iskandar Setiawan <alviro.iskandar@gmail.com>
 */

#include <teavpn2/gui/gui.h>
#include <string.h>
#include <pthread.h>
#include <teavpn2/client/common.h>

GtkWidget *s_w_label_path;
GtkWidget *s_w_button_connect;
GtkWidget *s_w_text_logger;
GtkWidget *s_w_label_status;

static void *run_vpn_thread(__maybe_unused void *p)
{
	int ret = -EINVAL;
	const char *cfg_file;
	struct cli_cfg cfg;

	cfg_file = gtk_label_get_label(GTK_LABEL(gui_home_get_label_path()));
	if (unlikely(!cfg_file))
		goto out;

	memset(&cfg, 0, sizeof(cfg));
	cfg.sys.cfg_file = cfg_file;
	ret = client_parse_cfg_file(cfg.sys.cfg_file, &cfg);
	if (unlikely(ret))
		goto out;

	ret = -ESOCKTNOSUPPORT;
	switch (cfg.sock.type) {
	case SOCK_UDP:
		ret = teavpn2_client_udp_run(&cfg);
		break;
	case SOCK_TCP:
		break;
	default:
		BUG();
		break;
	}
out:
	if (unlikely(ret))
		set_client_vpn_err_event(ret);
	return NULL;
}

static void button_connect_callback(GtkWidget *self, void *user_data)
{
	static pthread_t vpn_thread;
	const char *btn_label;
	GtkTextBuffer *txt_buf;
	GtkTextIter txt_iter;

	btn_label = gtk_button_get_label(GTK_BUTTON(self));
	if (BUG_ON(!btn_label))
		return;

	txt_buf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(gui_home_get_text_logger()));
	gtk_text_buffer_set_text(txt_buf, "", -1);
	gtk_text_buffer_get_end_iter(txt_buf, &txt_iter);
	gtk_text_buffer_create_mark(txt_buf, "main_log", &txt_iter, TRUE);

	/*
	 * When the button is clicked, disable it. The callback
	 * in the events.c is responsible to enable it.
	 */
	gtk_widget_set_sensitive(GTK_WIDGET(self), FALSE);

	if (btn_label[0] == 'C') {
		int ret;

		gtk_button_set_label(GTK_BUTTON(self), "Connecting...");
		ret = pthread_create(&vpn_thread, NULL, &run_vpn_thread, NULL);
		if (unlikely(ret)) {
			pr_err("pthread_create(): " PRERF, PREAR(ret));
			return;
		}

		ret = pthread_detach(vpn_thread);
		if (unlikely(ret))
			pr_err("pthread_detach(): " PRERF, PREAR(ret));

	} else if (btn_label[0] == 'D') {
stop_vpn:
		gtk_button_set_label(GTK_BUTTON(self), "Disconnecting...");
		teavpn2_client_udp_stop();
		pthread_kill(vpn_thread, SIGTERM);
	} else {
		BUG();
		goto stop_vpn;
	}

	(void) user_data;
}

static GtkWidget *box_top_create(void)
{
	GtkWidget *box;
	GtkWidget *frame_conf;
	static const struct gui_callback callbacks[] = {
		{
			.self		= &s_w_button_connect,
			.signal_name	= "clicked",
			.func		= button_connect_callback,
			.user_data	= NULL
		},
	};
	const size_t nr_callbacks = sizeof(callbacks) / sizeof(*callbacks);

	box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
	s_w_button_connect = gtk_button_new_with_label("Connect");
	frame_conf = gtk_frame_new("Configuration File");
	s_w_label_path = gtk_label_new(GUI_DEFAULT_CONFIG);

	gui_utils_set_callback(callbacks, nr_callbacks);

	gui_utils_set_margins(s_w_label_path, 5);
	gtk_widget_set_halign(s_w_button_connect, GTK_ALIGN_CENTER);
	gtk_widget_set_margin_top(s_w_button_connect, 5);

	gtk_container_add(GTK_CONTAINER(frame_conf), s_w_label_path);
	gtk_container_add(GTK_CONTAINER(box), frame_conf);
	gtk_container_add(GTK_CONTAINER(box), s_w_button_connect);
	gui_utils_set_margins(box, 5);

	return box;
}

static GtkWidget *box_btm_create(void)
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

void gui_home_insert_text_logger(const char *msg)
{
	GtkTextBuffer *buf;
	GtkTextMark *mark;
	static GtkTextIter iter;


	buf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(gui_home_get_text_logger()));

	gtk_text_buffer_get_end_iter(buf, &iter);
	gtk_text_buffer_insert(buf, &iter, msg, -1);
	gtk_text_iter_set_line_offset(&iter, 0);

	mark = gtk_text_buffer_get_mark(buf, "main_log");
	gtk_text_buffer_move_mark(buf, mark, &iter);
	gtk_text_view_scroll_mark_onscreen(GTK_TEXT_VIEW(gui_home_get_text_logger()),
					   mark);
}

void gui_home_create(GtkWidget *parent)
{
	gtk_box_pack_start(GTK_BOX(parent), box_top_create(), FALSE, FALSE, 0);
	gtk_box_pack_end(GTK_BOX(parent), box_btm_create(), TRUE, TRUE, 0);
}
