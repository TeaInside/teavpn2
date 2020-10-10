
#include <teavpn2/server/common.h>

#if defined(__linux__)
#  include "server/linux.h"
#else
#  error "Compiler is not supported!"
#endif
