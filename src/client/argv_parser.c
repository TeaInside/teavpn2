
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <teavpn2/client/common.h>

#define PARAM_DEBUG 1

static void set_default_config(teavpn_client_config *config);
static bool getopt_handler(int argc, char **argv, teavpn_client_config *config);

/**
 * @param int argc
 * @param char **argv
 * @param char **envp
 * @param teavpn_client_config *config
 * @return bool
 */
bool teavpn_client_argv_parser(int argc, char **argv, char **envp, teavpn_client_config *config)
{

  if (argc == 1) {
    printf("Usage: %s [options]\n", argv[0]);
    return false;
  }

  bool ret;
  set_default_config(config);
  ret = getopt_handler(argc, argv, config);

  return ret;
}

#ifdef PARAM_DEBUG
  #if PARAM_DEBUG
    #define pdebug(...) printf(__VA_ARGS__)
    #define pqdebug(A, B, C) printf("  Got "#A" = "B"\n", C);
  #else
    #define pdebug(...)
    #define pqdebug(...)
  #endif
#else
  #define pdebug(...)
  #define pqdebug(...)
#endif

const static struct option long_options[] = {
  /* Interface options. */  
  {"config",       required_argument, 0, 'c'},
  {"dev",          required_argument, 0, 'd'},
  {"mtu",          required_argument, 0, 'm'},
  {"inet4",        required_argument, 0, '4'},
  {"inet4-bcmask", required_argument, 0, 'b'},
  {"sock-type",    required_argument, 0, 's'},

  /* Socket options. */
  {"bind-addr",    required_argument, 0, 'h'},
  {"bind-port",    required_argument, 0, 'p'},

  /* Data options. */
  {"data-dir",     required_argument, 0, 'u'},

  {0, 0, 0, 0}
};

/**
 * @param int argc
 * @param char **argv
 * @param teavpn_client_config *config
 * @return bool
 */
static bool getopt_handler(int argc, char **argv, teavpn_client_config *config)
{
  int c;

  pdebug("Parsing argv...\n");
  while (1) {
    int this_option_optind = optind ? optind : 1;
    int option_index = 0;
    c = getopt_long(argc, argv, "h:d:c:m:4:b:p:s:u:", long_options, &option_index);

    if (c == -1)
      break;

    switch (c) {
      /* Interface options. */
      case 'c':
        config->config_file = optarg;
        pqdebug(config_file, "\"%s\"", optarg);
        break;
      case 'd':
        config->iface.dev = optarg;
        pqdebug(dev, "\"%s\"", optarg);
        break;
      case 'm':
        config->iface.mtu = atoi(optarg);
        pqdebug(mtu, "%d", config->iface.mtu);
        break;
      case '4':
        config->iface.inet4 = optarg;
        pqdebug(inet4, "\"%s\"", optarg);
        break;
      case 'b':
        config->iface.inet4_bcmask = optarg;
        pqdebug(inet4_bcmask, "\"%s\"", optarg);
        break;

      /* Socket options. */
      case 's':
        if (!strcmp(optarg, "tcp")) {
          config->socket_type = teavpn_sock_tcp;
        } else if (!strcmp(optarg, "udp")) {
          config->socket_type = teavpn_sock_udp;
        } else {
          printf("Invalid socket type: \"%s\"\n", optarg);
          return false;
        }
        pqdebug(bind_addr, "\"%s\"", optarg);
        break;
      case 'h':
        config->socket.server_addr = optarg;
        pqdebug(server_addr, "\"%s\"", optarg);
        break;
      case 'p':
        config->socket.server_port = (uint16_t)atoi(optarg);
        pqdebug(server_port, "%d", config->socket.server_port);
        break;

      case 'u':
        config->data_dir = optarg;
        pqdebug(data_dir, "\"%s\"", optarg);
        break;

      default:
        printf("?? getopt returned character code 0%o ??\n", c);
        return false;
        break;
    }
  }
  pdebug("Parsing argv finished!\n\n");
  return true;
}

static void set_default_config(teavpn_client_config *config)
{
  memset(config, 0, sizeof(teavpn_client_config));

  config->iface.dev = (char *)"tun0";
  config->iface.mtu = 1500;
  config->iface.inet4 = (char *)"10.8.0.1/24";
  config->iface.inet4_bcmask = (char *)"10.8.0.255";

  config->socket.server_addr = NULL;
  config->socket_type = teavpn_sock_tcp;
  config->socket.server_port = 55555;
}
