
#ifndef __TEAVPN2__SERVER__AUTH_H
#define __TEAVPN2__SERVER__AUTH_H

#include <stdbool.h>
#include <teavpn2/auth.h>
#include <teavpn2/server/common.h>


bool teavpn_server_get_auth(struct iface_cfg *iface, struct auth_pkt *auth,
			    struct srv_cfg *cfg);

#endif /* #ifndef __TEAVPN2__SERVER__AUTH_H */
