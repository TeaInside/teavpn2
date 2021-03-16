// SPDX-License-Identifier: GPL-2.0-only
/*
 *  teavpn2/license.c
 *
 *  License print
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#include <stdio.h>
#include <teavpn2/base.h>

static const char license_text_teavpn2[] = "\n\
https://github.com/TeaInside/teavpn2\n\
\n\
TeaVPN2 - Fast and Free VPN Software\n\
Copyright (C) 2021  Ammar Faizi\n\
\n\
This program is free software; you can redistribute it and/or modify\n\
it under the terms of the GNU General Public License as published by\n\
the Free Software Foundation; either version 2 of the License, or\n\
(at your option) any later version.\n\
\n\
This program is distributed in the hope that it will be useful,\n\
but WITHOUT ANY WARRANTY; without even the implied warranty of\n\
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n\
GNU General Public License for more details.\n\
\n\
You should have received a copy of the GNU General Public License along\n\
with this program; if not, write to the Free Software Foundation, Inc.,\n\
51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.\n\
";

int print_license(void)
{
	printf("%s", license_text_teavpn2);
	return 0;
}
