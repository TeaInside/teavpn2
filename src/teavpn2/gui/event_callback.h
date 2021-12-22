// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021  Alviro Iskandar Setiawan <alviro.iskandar@gmail.com>
 */

#ifndef TEAVPN2__GUI__EVENT_CALLBACKS_H
#define TEAVPN2__GUI__EVENT_CALLBACKS_H

extern void *client_udata;
extern void (*client_on_connect)(void);
extern void (*client_on_error)(int code);
extern void (*client_on_disconnect)(void);
extern void register_client_callbacks(void);

#ifdef CONFIG_GUI

static inline void invoke_client_on_connect(void)
{
	if (client_on_connect)
		client_on_connect();
}

static inline void invoke_client_on_disconnect(void)
{
	if (client_on_disconnect)
		client_on_disconnect();
}

static inline void invoke_client_on_error(int code)
{
	if (client_on_error)
		client_on_error(code);
}

#else

static inline void invoke_client_on_connect(void)
{
}

static inline void invoke_client_on_disconnect(void)
{
}

static inline void invoke_client_on_error(int code)
{
	(void) code;
}

#endif

#endif /* #ifndef TEAVPN2__GUI__EVENT_CALLBACKS_H */
