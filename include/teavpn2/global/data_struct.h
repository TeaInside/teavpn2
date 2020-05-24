
#ifndef TEAVPN__GLOBAL__DATA_STRUCT_H
#define TEAVPN__GLOBAL__DATA_STRUCT_H

#include <teavpn2/server/data_struct.h>
#include <teavpn2/client/data_struct.h>

#define CLI_PKT_RSIZE(ADD_SIZE) ((sizeof(teavpn_cli_pkt) - 1) + ADD_SIZE)
#define SRV_PKT_RSIZE(ADD_SIZE) ((sizeof(teavpn_srv_pkt) - 1) + ADD_SIZE)

#endif
