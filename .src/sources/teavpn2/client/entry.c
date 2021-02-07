
#include <string.h>
#include <teavpn2/server/argv.h>
#include <teavpn2/server/entry.h>
#include <teavpn2/server/config.h>

#if defined(__linux__)
# include <teavpn2/server/plat/linux/tcp.h>
#else
# error This compiler is not supported at the moment
#endif

int teavpn_client_entry(int argc, char *argv[])
{
}
