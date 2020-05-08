
#ifndef TEAVPN__SERVER__COMMON_H
#define TEAVPN__SERVER__COMMON_H

#include <stdbool.h>
#include <teavpn2/global/common.h>
#include <teavpn2/server/config.h>

bool teavpn_server_config_parser(char *ini_file, teavpn_server_config *config);

#endif
