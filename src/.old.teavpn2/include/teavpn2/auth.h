
#ifndef TEAVPN2__AUTH_H
#define TEAVPN2__AUTH_H

#include <teavpn2/__base.h>


struct auth_pkt {
	char	username[255 + 1];
	char	password[255 + 1];
};

STATIC_ASSERT(
	sizeof(struct auth_pkt) == (256 * 2),
	"Bad sizeof(struct auth_pkt)"
);

#endif /* #ifndef TEAVPN2__AUTH_H */
