
#include <string.h>
#include <arpa/inet.h>

#include <inih/ini.h>
#include <teavpn2/server/common.h>

extern server_tcp_state *g_state;

struct auth_parse {
  bool            failed;
  char            *filename;
  client_auth_tmp *auth_tmp;
};

inline static int auth_file_parser(
  void *user,
  const char *section,
  const char *name,
  const char *value,
  int lineno
);

bool tvpn_auth_tcp(
  auth_pkt *auth_p,
  tcp_channel *chan,
  client_auth_tmp *auth_tmp
)
{
  server_tcp_state *state  = g_state;
  server_cfg       *config;

  /* For string safety. */
  auth_p->username[254] = '\0';
  auth_p->password[254] = '\0';

  if (!state) {
    debug_log(0, "tvpn_auth_tcp error, g_state is NULL");
    return false;
  }

  config = state->config;

  {
    int ret;
    size_t cpwdl;
    struct auth_parse auth_dp;
    char auth_file[
      strlen(config->data_dir) +
      strlen(auth_p->username) + 16
    ];

    sprintf(auth_file, "%s/users/%s.ini", config->data_dir, auth_p->username);

    auth_dp.failed   = false;
    auth_dp.filename = auth_file;
    auth_dp.auth_tmp = auth_tmp;


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

    cpwdl = strlen(auth_dp.auth_tmp->password);

    if ((auth_p->password_len != cpwdl)
        || strncmp(auth_p->password, auth_dp.auth_tmp->password, cpwdl)) {
      debug_log(1, "[%s:%d] Wrong password!", HP_CC(chan));
      return false;
    }

    debug_log(
      1, "[%s:%d] Authenticated: "
      "{\"username\":\"%s\",\"ipv4\":\"%s\",\"ipv4_netmask\":\"%s\"}",
      HP_CC(chan),
      auth_p->username,
      auth_tmp->ipv4,
      auth_tmp->ipv4_netmask
    );

    return true;
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
  struct auth_parse *auth_dp  = (struct auth_parse *)user;
  client_auth_tmp   *auth_tmp = auth_dp->auth_tmp;

  #define RMATCH_S(STR) if (!strcmp(section, STR))
  #define RMATCH_N(STR) if (!strcmp(name, STR))

  RMATCH_S("auth") {

    RMATCH_N("username") {
      strncpy(auth_tmp->username, value, sizeof(auth_tmp->username));
    } else
    RMATCH_N("password") {
      strncpy(auth_tmp->password, value, sizeof(auth_tmp->password));
    } else
    RMATCH_N("secret_key") {
      strncpy(auth_tmp->secret_key, value, sizeof(auth_tmp->secret_key));
    } else {
      goto invalid_name;
    }

  } else
  RMATCH_S("ip_assign") {

    RMATCH_N("ipv4") {
      strncpy(auth_tmp->ipv4, value, sizeof(auth_tmp->ipv4));
    } else
    RMATCH_N("ipv4_netmask") {
      strncpy(auth_tmp->ipv4_netmask, value, sizeof(auth_tmp->ipv4_netmask));
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
