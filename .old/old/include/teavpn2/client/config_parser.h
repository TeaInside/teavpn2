
#ifndef TEAVPN__CLIENT__CONFIG_PARSER_H
#define TEAVPN__CLIENT__CONFIG_PARSER_H

#include <stdbool.h>
#include <teavpn2/client/config.h>

bool teavpn_client_config_parser(char *ini_file, teavpn_client_config *config);

#endif
