
#ifndef TEAVPN2__SERVER__COMMON_H
#define TEAVPN2__SERVER__COMMON_H

#include <teavpn2/global/common.h>
#include <teavpn2/server/config.h>

int
tsrv_run(srv_cfg *cfg);

void
tsrv_clean_up();

#endif
