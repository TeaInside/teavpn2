// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021  Khaerul Ilham <khaerulilham163@gmail.com>
 * Copyright (C) 2021  Alviro Iskandar Setiawan <alviro.iskandar@gmail.com>
 */

#include <teavpn2/gui/gui.h>
#include <string.h>
#include <pthread.h>


static void *run_vpn_thread(void *user_data)
{
	struct gui *gui = (struct gui *) user_data;
	int ret = -EINVAL;
	struct cli_cfg *cfg = &gui->app.cli_cfg;

	memset(cfg, 0, sizeof(struct cli_cfg));
	cfg->sys.cfg_file = gui->app.cfg_file->str;
	ret = client_parse_cfg_file(cfg->sys.cfg_file, cfg);
	if (unlikely(ret))
		goto out;

	ret = -ESOCKTNOSUPPORT;
	switch (cfg->sock.type) {
	case SOCK_UDP:
		ret = teavpn2_client_udp_run(cfg);
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

static void btn_connect_callback(GtkWidget *self, void *user_data)
{
	struct gui *gui = (struct gui *) user_data;
	static pthread_t vpn_thread;
	const char *btn_label;
	GtkTextBuffer *txt_buf;
	GtkTextIter txt_iter;

	btn_label = gtk_button_get_label(GTK_BUTTON(self));
	if (BUG_ON(!btn_label))
		return;

	txt_buf = gui->app.txt_buffer_log;
	//gtk_text_buffer_set_text(txt_buf, "", -1);
	gtk_text_buffer_get_end_iter(txt_buf, &txt_iter);
	gtk_text_buffer_create_mark(txt_buf, "main_log", &txt_iter, TRUE);

	/*
	 * When the button is clicked, disable them. The callback
	 * in the events.c is responsible to enable them.
	 */
	gtk_widget_set_sensitive(GTK_WIDGET(self), FALSE);
	gtk_widget_set_sensitive(gui->header_btn_open, FALSE);

	if (btn_label[0] == 'C') {
		int ret;

		pr_notice("Connecting...");
		gtk_button_set_label(GTK_BUTTON(self), "Connecting...");
		ret = pthread_create(&vpn_thread, NULL, &run_vpn_thread, gui);
		if (unlikely(ret)) {
			pr_err("pthread_create(): " PRERF, PREAR(ret));
			return;
		}

		ret = pthread_detach(vpn_thread);
		if (unlikely(ret))
			pr_err("pthread_detach(): " PRERF, PREAR(ret));

	} else if (btn_label[0] == 'D') {
stop_vpn:
		pr_notice("Disconnecting...");
		gtk_button_set_label(GTK_BUTTON(self), "Disconnecting...");
		teavpn2_client_udp_stop();
		pthread_kill(vpn_thread, SIGTERM);
	} else {
		BUG();
		goto stop_vpn;
	}
}

static GtkWidget *box_top_create(struct gui *g)
{
	GtkWidget *box;
	GtkWidget *frame_conf;
	const struct gui_callback callbacks[] = {
		GUI_CALLBACK(&g->home_btn_connect, "clicked",
			     btn_connect_callback, g),
	};

	box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
	g->home_btn_connect = gtk_button_new_with_label("Connect");
	frame_conf = gtk_frame_new("Configuration File");
	g->home_lbl_path = gtk_label_new(g->app.cfg_file->str);

	gui_utils_set_callback(callbacks, G_N_ELEMENTS(callbacks));

	gtk_widget_set_margin_bottom(g->home_lbl_path, 10);
	gtk_widget_set_margin_start(g->home_lbl_path, 5);
	gtk_widget_set_margin_end(g->home_lbl_path, 5);

	gtk_widget_set_halign(g->home_btn_connect, GTK_ALIGN_CENTER);
	gtk_widget_set_margin_top(g->home_btn_connect, 5);

	gtk_container_add(GTK_CONTAINER(frame_conf), g->home_lbl_path);
	gtk_container_add(GTK_CONTAINER(box), frame_conf);
	gtk_container_add(GTK_CONTAINER(box), g->home_btn_connect);

	gtk_widget_set_margin_start(box, 5);
	gtk_widget_set_margin_end(box, 5);

	return box;
}

static GtkWidget *box_btm_create(struct gui *g)
{
	GtkWidget *box;
	GtkWidget *frame_log, *scroller;

	box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
	frame_log = gtk_frame_new("Log:");
	scroller = gtk_scrolled_window_new(NULL, NULL);
	g->home_txt_logger = gtk_text_view_new_with_buffer(g->app.txt_buffer_log);

	gtk_text_view_set_editable(GTK_TEXT_VIEW(g->home_txt_logger), FALSE);
	gtk_text_view_set_monospace(GTK_TEXT_VIEW(g->home_txt_logger), TRUE);
	gtk_text_view_set_overwrite(GTK_TEXT_VIEW(g->home_txt_logger), TRUE);
	gtk_widget_set_vexpand(g->home_txt_logger, TRUE);
	gtk_container_add(GTK_CONTAINER(scroller), g->home_txt_logger);
	gtk_container_add(GTK_CONTAINER(frame_log), scroller);
	gtk_container_add(GTK_CONTAINER(box), frame_log);

	gtk_widget_set_margin_bottom(frame_log, 5);
	gtk_widget_set_margin_start(frame_log, 5);
	gtk_widget_set_margin_end(frame_log, 5);

	return box;
}

void gui_home_insert_txt_logger(struct gui *g, const char *msg)
{
	GtkTextMark *mark;
	static GtkTextIter iter;


	gtk_text_buffer_get_end_iter(g->app.txt_buffer_log, &iter);
	gtk_text_buffer_insert(g->app.txt_buffer_log, &iter, msg, -1);
	gtk_text_iter_set_line_offset(&iter, 0);

	mark = gtk_text_buffer_get_mark(g->app.txt_buffer_log, "main_log");
	gtk_text_buffer_move_mark(g->app.txt_buffer_log, mark, &iter);
	gtk_text_view_scroll_mark_onscreen(GTK_TEXT_VIEW(g->home_txt_logger),
					   mark);
}

void gui_home_create(struct gui *g)
{
	gtk_box_pack_start(g->home, box_top_create(g), FALSE, FALSE, 0);
	gtk_box_pack_end(g->home, box_btm_create(g), TRUE, TRUE, 0);
}
