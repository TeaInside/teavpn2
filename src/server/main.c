
#include <signal.h>
#include <teavpn2/server/common.h>


inline static void teavpn_sig_handler(int sig);
static teavpn_srv_cfg *config_p;

/**
 * @param int argc
 * @param char *argv[]
 * @param char *envp[]
 * @return int
 */
int main(int argc, char *argv[], char *envp[])
{
  teavpn_srv_cfg config;

  config_p = &config;
  bzero(&config, sizeof(teavpn_srv_cfg));

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
}


/**
 * @param int sig
 * @return void
 */
inline static void teavpn_sig_handler(int sig)
{
}
