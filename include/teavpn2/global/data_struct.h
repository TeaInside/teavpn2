
#ifndef TEAVPN__GLOBAL__DATA_STRUCT_H
#define TEAVPN__GLOBAL__DATA_STRUCT_H

#include <teavpn2/server/data_struct.h>
#include <teavpn2/client/data_struct.h>

#define CLI_PKT_HSIZE (sizeof(teavpn_cli_pkt) - 1)
#define SRV_PKT_HSIZE (sizeof(teavpn_srv_pkt) - 1)

#endif
