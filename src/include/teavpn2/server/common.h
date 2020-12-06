
#ifndef TEAVPN2__SERVER__COMMON_H
#define TEAVPN2__SERVER__COMMON_H

#include <teavpn2/global/common.h>

#define DO_INCLUDE_CONFIG_H
#include <teavpn2/server/config.h>
#undef DO_INCLUDE_CONFIG_H

int
tsrv_start(int argc, char *argv[]);

bool
tsrv_argv_parser(int argc, char *argv[], srv_cfg *cfg);

bool
tsrv_cfg_load(const char *cfg_file, srv_cfg *cfg);

#endif /* #ifndef TEAVPN2__SERVER__COMMON_H */
