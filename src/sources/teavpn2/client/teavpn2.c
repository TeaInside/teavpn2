
#include <linux/if.h>
#include <linux/if_tun.h>

#include <teavpn2/client/common.h>


inline static bool tvpn_client_config_validate(client_cfg *config);


int tvpn_client_run(client_cfg *config)
{
  int ret = 1;

  debug_log(4, "Validating client config...");
  if (!tvpn_client_config_validate(config)) {
    goto ret;
  }

  switch (config->sock.type) {
    case sock_tcp:
      ret = tvpn_client_tcp_run(config);
      goto ret;

    case sock_udp:
      printf("UDP socket is not supported yet!\n");
      goto ret;

    default:
      printf("Invalid socket type %d\n", config->sock.type);
      goto ret;
  }


  ret:
  return ret;
}


inline static bool tvpn_server_config_validate(server_cfg *config)
{

}
