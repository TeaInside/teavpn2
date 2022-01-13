// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021  Alviro Iskandar Setiawan <alviro.iskandar@gmail.com>
 */

#include <teavpn2/gui/gui.h>

static struct gui *g_gui;
int g_client_err_code = 0;
struct tmutex g_client_vpn_state_lock;
uint8_t g_client_vpn_state = CLIENT_EVENT_IDLE;


int teavpn2_gui_event_init(struct gui *gui)
{
	g_gui = gui;
	return mutex_init(&g_client_vpn_state_lock, NULL);
}

int teavpn2_gui_event_destroy(void)
{
	mutex_destroy(&g_client_vpn_state_lock);
	return 0;
}

static void client_event_connected_cb(void)
	__must_hold(&g_client_vpn_state_lock)
{
	GtkWidget *btn;

	btn = gui_home_get_button_connect();
	if (!btn) {
		pr_err("Cannot get button connect widget");
		return;
	}
	gtk_button_set_label(GTK_BUTTON(btn), "Disconnect");
	gtk_widget_set_sensitive(GTK_WIDGET(btn), TRUE);
	pr_notice("Connected!");
}

static void client_event_disconnected_cb(void)
	__must_hold(&g_client_vpn_state_lock)
{
	GtkWidget *btn;

	btn = gui_home_get_button_connect();
	if (!btn) {
		pr_err("Cannot get button connect widget");
		return;
	}
	gtk_button_set_label(GTK_BUTTON(btn), "Connect");
	gtk_widget_set_sensitive(GTK_WIDGET(btn), TRUE);
	pr_notice("Disconnected!");
}

static void client_event_error_cb(int err_code)
	__must_hold(&g_client_vpn_state_lock)
{
	GtkWidget *btn;

	btn = gui_home_get_button_connect();
	if (!btn) {
		pr_err("Cannot get button connect widget");
		return;
	}
	gtk_button_set_label(GTK_BUTTON(btn), "Connect");
	gtk_widget_set_sensitive(GTK_WIDGET(btn), TRUE);
	pr_err(PRERF, PREAR(-err_code));
}

gboolean client_callback_event_loop(void *user_data)
	__acquires(&g_client_vpn_state_lock)
	__releases(&g_client_vpn_state_lock)
{
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
		gui_home_insert_text_logger(prbuf);
	}

	switch (g_client_vpn_state) {
	case CLIENT_EVENT_IDLE:
		cpu_relax();
		goto skip_set;
	case CLIENT_EVENT_CONNECTED:
		client_event_connected_cb();
		break;
	case CLIENT_EVENT_DISCONNECTED:
		client_event_disconnected_cb();
		break;
	case CLIENT_EVENT_ERROR:
		client_event_error_cb(g_client_err_code);
		break;
	default:
		BUG();
		break;
	}

	g_client_vpn_state = CLIENT_EVENT_IDLE;

skip_set:
	mutex_unlock(&g_client_vpn_state_lock);
	(void) user_data;
	return TRUE;
}
