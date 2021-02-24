
#include <teavpn2/server/iface.h>

#if defined(__linux__)
#  include "init/linux.h"
#else
#  error Compiler is not supported!
#endif


/**
 * @param srv_iface_cfg *iface
 * @return int
 */
int
srv_iface_init(srv_iface_cfg *iface)
{

}
