// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021  Ammar Faizi
 */

#ifndef TEAVPN2__CLIENT__LINUX__UDP_H
#define TEAVPN2__CLIENT__LINUX__UDP_H

#include <teavpn2/client/common.h>

struct cli_udp_state {
	int			udp_fd;
	struct cli_cfg		*cfg;
};

#endif /* #ifndef TEAVPN2__CLIENT__LINUX__UDP_H */
