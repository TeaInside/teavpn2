
#include <signal.h>
#include <teavpn2/global/iface.h>
#include <teavpn2/server/common.h>
#include <teavpn2/server/socket/tcp.h>

#define ARENA_SIZE (1024 * 30)

static inline void teavpn_sig_handler(int sig);
static teavpn_server_config *config_p;

/**
 * @param int argc
 * @param char *argv[]
 * @param char *envp[]
 * @return int
 */
int main(int argc, char *argv[], char *envp[])
{
  char arena[ARENA_SIZE]; /* We create our function to treat this like heap. */
  teavpn_server_config config;

  config_p = &config;
  config.mstate = NULL;

  init_arena(arena, ARENA_SIZE);

  if (!teavpn_server_argv_parser(argc, argv, envp, &config)) {
    return 1;
  }

  if (config.config_file != NULL) {
    if (!teavpn_server_config_parser(config.config_file, &config)) {
      return 1;
    }
  }

  signal(SIGINT, teavpn_sig_handler);
  signal(SIGHUP, teavpn_sig_handler);
  signal(SIGQUIT, teavpn_sig_handler);

  #ifdef TEAVPN_DEBUG
    print_server_config(&config);
  #endif

  return teavpn_server_run(&config);
}


/**
 * @param int sig
 * @return void
 */
static inline void teavpn_sig_handler(int sig)
{
  server_tcp_mstate *mstate = (server_tcp_mstate *)config_p->mstate;
  teavpn_iface_clean_up(&(config_p->iface));

  if (mstate != NULL) {
    mstate->stop_all = true;
  }
}
