
#include <stdio.h>

static inline void
show_usage();


int
main(int argc, char *argv[])
{

  if (argc < 2) {
    show_usage();
    return 0;
  }

  
  return 0;
}

/**
 * @param const char *app
 * @return void
 */
static inline void
show_usage(const char *app)
{
  printf("Usage: %s [client|server] <options>\n", app);
}
