
#include <stdio.h>
#include <string.h>

#include <teavpn2/server/common.h>
#include <teavpn2/client/common.h>
#include <teavpn2/global/helpers/memory.h>

#ifndef ARENA_SIZE
#  define ARENA_SIZE (4096)
#endif

inline static void
show_usage(const char *app);

const char *app_name = NULL;

/**
 * @param int  argc
 * @param char *argv[]
 * @return int
 */
int
main(int argc, char *argv[])
{
  if (argc == 1) {
    goto ret;
  }

  {
    char arena[ARENA_SIZE];
    ar_init(arena, ARENA_SIZE);

    app_name = argv[0];

    if (strcmp(argv[1], "server") == 0) {
      return tsrv_start(argc - 1, &(argv[1]));
    } else
    if (strcmp(argv[1], "client") == 0) {
      return tcli_start(argc - 1, &(argv[1]));
    } else {
      printf("Invalid action: \"%s\"\n", argv[1]);
    }
  }

ret:
  show_usage(argv[0]);
  return 1;
}

/**
 * @param const char *app
 * @return void
 */
inline static void
show_usage(const char *app)
{
  printf("Usage: %s [client|server] [options]\n", app);
  printf("\n");
  printf("TeaVPN2 (An open source VPN software).\n");
  printf("\n");
  printf("  %s client --help\tFor client usage information.\n", app);
  printf("  %s server --help\tFor server usage information.", app);
  printf("\n");
}
