
#ifndef __TEAVPN2__AUTH_H
#define __TEAVPN2__AUTH_H

struct auth_pkt {
	char	username[255 + 1];
	char	password[255 + 1];
};

#endif /* #ifndef __TEAVPN2__AUTH_H */
