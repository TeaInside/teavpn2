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
