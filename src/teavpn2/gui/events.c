// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021  Alviro Iskandar Setiawan <alviro.iskandar@gmail.com>
 */

#include <teavpn2/gui/gui.h>

int g_client_err_code = 0;
struct tmutex g_client_vpn_state_lock;
uint8_t g_client_vpn_state = CLIENT_EVENT_IDLE;


int teavpn2_gui_event_init(void)
{
	return mutex_init(&g_client_vpn_state_lock, NULL);
}

int teavpn2_gui_event_destroy(void)
{
	mutex_destroy(&g_client_vpn_state_lock);
	return 0;
}

static void client_event_connected_cb(struct gui *g)
	__must_hold(&g_client_vpn_state_lock)
{
	char lbl_stat[0x250u];
	struct cli_cfg *cfg = &g->app.cli_cfg;


	if (!g->home_btn_connect) {
		pr_err("Cannot get button connect widget");
		return;
	}

	g_snprintf(lbl_stat, sizeof(lbl_stat), "Connected to \"%s@%s:%hu\"",
		   cfg->auth.username, cfg->sock.server_addr,
		   cfg->sock.server_port);

	g->app.cli_state = CLIENT_STATE_CONNECTED;
	gtk_button_set_label(GTK_BUTTON(g->home_btn_connect), "Disconnect");
	gtk_label_set_label(GTK_LABEL(g->home_lbl_status), lbl_stat);
	gtk_widget_set_sensitive(g->home_btn_connect, TRUE);
}

static void client_event_disconnected_cb(struct gui *g)
	__must_hold(&g_client_vpn_state_lock)
{
	if (!g->home_btn_connect) {
		pr_err("Cannot get button connect widget");
		return;
	}

	g->app.cli_state = CLIENT_STATE_DISCONNECTED;
	gtk_button_set_label(GTK_BUTTON(g->home_btn_connect), "Connect");
	gtk_label_set_label(GTK_LABEL(g->home_lbl_status), "Disconnected");
	gtk_widget_set_sensitive(g->home_btn_connect, TRUE);
	gtk_widget_set_sensitive(g->header_btn_open, TRUE);
}

static void client_event_error_cb(struct gui *g, int err_code)
	__must_hold(&g_client_vpn_state_lock)
{
	if (!g->home_btn_connect) {
		pr_err("Cannot get button connect widget");
		return;
	}

	g->app.cli_state = CLIENT_STATE_DISCONNECTED;
	gtk_button_set_label(GTK_BUTTON(g->home_btn_connect), "Connect");
	gtk_label_set_label(GTK_LABEL(g->home_lbl_status), "Disconnected");
	gtk_widget_set_sensitive(g->home_btn_connect, TRUE);
	gtk_widget_set_sensitive(g->header_btn_open, TRUE);
	pr_err(PRERF, PREAR(-err_code));
}

gboolean client_callback_event_loop(void *user_data)
	__acquires(&g_client_vpn_state_lock)
	__releases(&g_client_vpn_state_lock)
{
	struct gui *gui = (struct gui *) user_data;
	unsigned try_num = 0;
	const unsigned max_try = 10;
	static char prbuf[4096];
	size_t prbuf_len;

	while (unlikely(mutex_trylock(&g_client_vpn_state_lock))) {
		cpu_relax();
		if (unlikely(try_num++ >= max_try))
			return TRUE;
	}

	prbuf_len = gui_pr_consume_buffer(prbuf, sizeof(prbuf) - 1);
	if (prbuf_len) {
		prbuf[prbuf_len] = '\0';
		gui_home_insert_txt_logger(gui, prbuf);
	}

	switch (g_client_vpn_state) {
	case CLIENT_EVENT_IDLE:
		cpu_relax();
		goto skip_set;
	case CLIENT_EVENT_CONNECTED:
		client_event_connected_cb(gui);
		break;
	case CLIENT_EVENT_DISCONNECTED:
		client_event_disconnected_cb(gui);
		break;
	case CLIENT_EVENT_ERROR:
		client_event_error_cb(gui, g_client_err_code);
		break;
	default:
		BUG();
		break;
	}

	g_client_vpn_state = CLIENT_EVENT_IDLE;

skip_set:
	mutex_unlock(&g_client_vpn_state_lock);
	return TRUE;
}
