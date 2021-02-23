
#ifndef TEAVPN2__CLIENT__COMMON_H
#define TEAVPN2__CLIENT__COMMON_H

#include <teavpn2/global/common.h>

#define DO_INCLUDE_CONFIG_H
#include <teavpn2/client/config.h>
#undef DO_INCLUDE_CONFIG_H

int
tcli_start(int argc, char *argv[]);

bool
tcli_argv_parser(int argc, char *argv[], cli_cfg *cfg);

bool
tcli_cfg_load(const char *cfg_file, cli_cfg *cfg);

#endif /* #ifndef TEAVPN2__CLIENT__COMMON_H */
