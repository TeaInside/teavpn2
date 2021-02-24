
#include <teavpn2/global/helpers/iface.h>

#if defined(__linux__)
#  include "iface/linux.h"
#else
#  error "Compiler is not supported!"
#endif
