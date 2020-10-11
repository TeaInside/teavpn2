
#include <teavpn2/client/common.h>

#if defined(__linux__)
#  include "client/linux.h"
#else 
#  error "Compiler is not supported!"
#endif
