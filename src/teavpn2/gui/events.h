// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021  Alviro Iskandar Setiawan <alviro.iskandar@gmail.com>
 */

#ifndef TEAVPN2__GUI__EVENTS_H
#define TEAVPN2__GUI__EVENTS_H

#include <teavpn2/gui/gui.h>
#include <teavpn2/mutex.h>

enum {
	CLIENT_EVENT_IDLE		= 0,
	CLIENT_EVENT_CONNECTED		= 1,
	CLIENT_EVENT_DISCONNECTED	= 2,
	CLIENT_EVENT_ERROR		= 3,
};

struct gui;

extern int g_client_err_code;
extern uint8_t g_client_vpn_state;
extern struct tmutex g_client_vpn_state_lock;
extern int teavpn2_gui_event_init(struct gui *gui);
extern int teavpn2_gui_event_destroy(void);

#ifdef CONFIG_GUI

extern gboolean client_callback_event_loop(void *data);

static inline void set_client_vpn_event(uint8_t state)
{
	assert(state < CLIENT_EVENT_ERROR);
	mutex_lock(&g_client_vpn_state_lock);
	g_client_vpn_state = state;
	mutex_unlock(&g_client_vpn_state_lock);
}

static inline void set_client_vpn_err_event(int err_code)
{
	mutex_lock(&g_client_vpn_state_lock);
	g_client_err_code = err_code;
	g_client_vpn_state = CLIENT_EVENT_ERROR;
	mutex_unlock(&g_client_vpn_state_lock);
}

#else /* #ifdef CONFIG_GUI */

static inline void set_client_vpn_event(uint8_t state)
{
	(void) state;
}

static inline void set_client_vpn_err_event(int err_code)
{
	(void) err_code;
}

#endif /* #ifdef CONFIG_GUI */

#endif /* #ifndef TEAVPN2__GUI__EVENTS_H */
