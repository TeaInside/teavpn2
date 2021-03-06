
#include <stdio.h>
#include <teavpn2/base.h>


static const char teavpn2[] = "\n\
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


static const char inih[] = "\n\
https://github.com/benhoyt/inih\n\
\n\
The \"inih\" library is distributed under the New BSD license:\n\
\n\
Copyright (c) 2009, Ben Hoyt\n\
All rights reserved.\n\
\n\
Redistribution and use in source and binary forms, with or without\n\
modification, are permitted provided that the following conditions are met:\n\
    * Redistributions of source code must retain the above copyright\n\
      notice, this list of conditions and the following disclaimer.\n\
    * Redistributions in binary form must reproduce the above copyright\n\
      notice, this list of conditions and the following disclaimer in the\n\
      documentation and/or other materials provided with the distribution.\n\
    * Neither the name of Ben Hoyt nor the names of its contributors\n\
      may be used to endorse or promote products derived from this software\n\
      without specific prior written permission.\n\
\n\
THIS SOFTWARE IS PROVIDED BY BEN HOYT ''AS IS'' AND ANY\n\
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED\n\
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE\n\
DISCLAIMED. IN NO EVENT SHALL BEN HOYT BE LIABLE FOR ANY\n\
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES\n\
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;\n\
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND\n\
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT\n\
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS\n\
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.\n\
";

const char invalid[] = "Invalid license index\n";

int print_license(unsigned short i)
{
	int retval = 0;
	const char *p = NULL;

	switch (i) {
	case 0: p = teavpn2; break;
	case 1: p = inih; break;
	default:
		p = invalid;
		retval = 1;
		break;
	}

	puts(p);
	return retval;
}
