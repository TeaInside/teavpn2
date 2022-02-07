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
	int ret;
	struct gui *gui = (struct gui *) user_data;
	static pthread_t vpn_thread;


	/*
	 * When the button is clicked, disable them. The callback
	 * in the events.c is responsible to enable them.
	 */
	gtk_widget_set_sensitive(GTK_WIDGET(self), FALSE);
	gtk_widget_set_sensitive(gui->header_btn_open, FALSE);

	switch (gui->app.cli_state) {
	case CLIENT_STATE_DISCONNECTED:
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
		break;

	case CLIENT_STATE_CONNECTED:
stop_vpn:
		pr_notice("Disconnecting...");
		gtk_button_set_label(GTK_BUTTON(self), "Disconnecting...");
		teavpn2_client_udp_stop();
		pthread_kill(vpn_thread, SIGTERM);
		break;

	default:
		BUG();
		goto stop_vpn;
	}
}

void gui_home_insert_txt_logger(struct gui *g, const char *msg)
{
	GtkTextMark *mark;
	GtkTextIter iter;
	GtkTextBuffer *txt_buffer_log = g->app.txt_buffer_log;


	gtk_text_buffer_get_end_iter(txt_buffer_log, &iter);
	gtk_text_buffer_insert(txt_buffer_log, &iter, msg, -1);
	gtk_text_iter_set_line_offset(&iter, 0);

	mark = gtk_text_buffer_get_mark(txt_buffer_log, "main_log");
	gtk_text_buffer_move_mark(txt_buffer_log, mark, &iter);
	gtk_text_view_scroll_mark_onscreen(GTK_TEXT_VIEW(g->home_txt_logger),
					   mark);
}

void gui_home_create(struct gui *g)
{
	GtkBox *home = g->home;
	GtkWidget *frame_conf, *frame_log, *scroller;
	GtkTextIter txt_iter;
	const struct gui_callback callbacks[] = {
		GUI_CALLBACK(&g->home_btn_connect, "clicked",
			     btn_connect_callback, g),
	};


	frame_conf = g_object_new(GTK_TYPE_FRAME,
				  "label", "Configuration File",
				  "margin-top", 5,
				  "margin-start", 5,
				  "margin-end", 5, NULL);
	g->home_lbl_path = g_object_new(GTK_TYPE_LABEL,
					"label", g->app.cfg_file->str,
					"parent", frame_conf,
					"margin-bottom", 10,
					"margin-start", 5,
					"margin-end", 5, NULL);
	g->home_btn_connect = g_object_new(GTK_TYPE_BUTTON,
					   "label", "Connect",
					   "halign", GTK_ALIGN_CENTER, NULL);
	frame_log = g_object_new(GTK_TYPE_FRAME,
				 "label", "Log:",
				 "margin-start", 5,
				 "margin-end", 5, NULL);
	scroller = g_object_new(GTK_TYPE_SCROLLED_WINDOW,
				"parent", frame_log, NULL);
	g->home_txt_logger = g_object_new(GTK_TYPE_TEXT_VIEW,
					  "parent", scroller,
					  "vexpand", TRUE,
					  "monospace", TRUE,
					  "editable", FALSE,
					  "buffer", g->app.txt_buffer_log, NULL);
	g->home_lbl_status = g_object_new(GTK_TYPE_LABEL,
					  "label", "Disconnected",
					  "wrap", TRUE,
					  "selectable", TRUE,
					  "margin-bottom", 5, NULL);

	gtk_text_buffer_get_end_iter(g->app.txt_buffer_log, &txt_iter);
	gtk_text_buffer_create_mark(g->app.txt_buffer_log, "main_log",
				    &txt_iter, TRUE);


	gtk_box_pack_start(home, frame_conf, FALSE, FALSE, 0);
	gtk_box_pack_start(home, g->home_btn_connect, FALSE, FALSE, 0);
	gtk_box_pack_start(home, frame_log, TRUE, TRUE, 0);
	gtk_box_pack_end(home, g->home_lbl_status, FALSE, FALSE, 0);

	gui_utils_set_callback(callbacks, G_N_ELEMENTS(callbacks));
}
