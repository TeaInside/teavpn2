
#include <signal.h>
#include <teavpn2/global/iface.h>
#include <teavpn2/client/common.h>
#include <teavpn2/client/socket/tcp.h>

#define ARENA_SIZE (1024 * 30)

inline static void teavpn_sig_handler(int sig);
static teavpn_client_config *config_p;

/**
 * @param int argc
 * @param char *argv[]
 * @param char *envp[]
 * @return int
 */
int main(int argc, char *argv[], char *envp[])
{
  char arena[ARENA_SIZE]; /* We create our function to treat this like heap. */
  teavpn_client_config config;

  config_p = &config;
  config.mstate = NULL;

  init_arena(arena, ARENA_SIZE);

  if (!teavpn_client_argv_parser(argc, argv, envp, &config)) {
    return 1;
  }

  if (config.config_file != NULL) {
    if (!teavpn_client_config_parser(config.config_file, &config)) {
      return 1;
    }
  }

  #ifdef TEAVPN_DEBUG
    print_client_config(&config);
  #endif

  return teavpn_client_run(&config);
}


/**
 * @param int sig
 * @return void
 */
inline static void teavpn_sig_handler(int sig)
{
  client_tcp_mstate *mstate = (client_tcp_mstate *)config_p->mstate;
  teavpn_iface_clean_up(&(config_p->iface));

  if (mstate != NULL) {
    mstate->stop_all = true;
  }
}
