
#include <string.h>

#include <inih/ini.h>
#include <teavpn2/server/common.h>

extern server_tcp_state *g_state;

struct auth_parse {
  bool        failed;
  char        *filename;
  tcp_channel *chan;
};

inline static int auth_file_parser(
  void *user,
  const char *section,
  const char *name,
  const char *value,
  int lineno
);

bool tvpn_auth_tcp(char *username, char *password, tcp_channel *chan)
{
  server_tcp_state *state  = g_state;
  server_cfg       *config;

  if (!state) {
    debug_log(0, "tvpn_auth_tcp error, g_state is NULL");
    return false;
  }

  config = state->config;

  {
    int ret;
    struct auth_parse auth_dp;
    char auth_file[strlen(config->data_dir) + strnlen(username, 255) + 16];

    sprintf(auth_file, "%s/users/%s.ini", config->data_dir, username);

    auth_dp.failed   = false;
    auth_dp.filename = auth_file;
    auth_dp.chan     = chan;


    ret = ini_parse(auth_file, auth_file_parser, (void *)&auth_dp);

    if (ret < 0) {
      debug_log(0, "[%s:%d] Auth error, file \"%s\" does not exist", HP_CC(chan),
        auth_file);
      return false;
    }

    if (auth_dp.failed) {
      debug_log(0, "[%s:%d] Error loading auth file!", HP_CC(chan));
      return false;
    }
  }
}

inline static int auth_file_parser(
  void *user,
  const char *section,
  const char *name,
  const char *value,
  int lineno
)
{
  struct auth_parse *auth_dp = (struct auth_parse *)user;
  tcp_channel       *chan    = auth_dp->chan;

  #define RMATCH_S(STR) if (!strcmp(section, STR))
  #define RMATCH_N(STR) if (!strcmp(name, STR))

  RMATCH_S("auth") {

    RMATCH_N("username") {

    } else
    RMATCH_N("password") {

    } else
    RMATCH_N("secret_key") {

    } else {
      goto invalid_name;
    }

  } else
  RMATCH_S("ip_assign") {

    RMATCH_N("ipv4") {

    } else
    RMATCH_N("ipv4_bcmask") {

    } else {
      goto invalid_name;
    }

  } else {
    goto invalid_name;
  }

  return 1;

invalid_name:
  debug_log(0,
    "Invalid name: \"%s\" in section \"%s\" on line %d in \"%s\"",
    name,
    section,
    lineno,
    auth_dp->filename
  );
  auth_dp->failed = true;
  return 0;
}
