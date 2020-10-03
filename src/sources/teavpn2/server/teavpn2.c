
#include <linux/if.h>
#include <linux/if_tun.h>

#include <teavpn2/server/common.h>


inline static bool tvpn_server_config_validate(server_cfg *config);


int tvpn_server_run(server_cfg *config)
{
  int ret = 1;
  server_state *state = (server_state *)t_ar_alloc(sizeof(server_state));

  if (!tvpn_server_config_validate(config)) {
    goto ret;
  }


  {
    state->tun_fds = (int *)t_ar_alloc(sizeof(int) * 10);


    /* Initialize TUN/TAP interface. */
    if (tun_alloc_mq(config->iface.dev, 10, state->tun_fds) < 0) {
      goto ret;
    }

    /* Detach all queue. */
    for (int i = 0; i < 10; i++) {
      tun_set_queue(state->tun_fds[i], 0);
    }
  }

  switch (config->sock.type) {
    case sock_tcp:
      ret = tvpn_server_tcp_run(state);
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
  {
    /* Validate server_iface_cfg. */
    server_iface_cfg *iface = &(config->iface);

    if (!iface->dev) {
      printf("config->iface.dev cannot be empty\n");
      return false;
    }

    if (!iface->ipv4) {
      printf("config->iface.ipv4 cannot be empty\n");
      return false; 
    }

    if (!iface->ipv4_bcmask) {
      printf("config->iface.ipv4_bcmask cannot be empty\n");
      return false; 
    }
  }

  {
    /* Validate server_socket_cfg. */
    server_socket_cfg *sock = &(config->sock);

    if (!sock->bind_addr) {
      printf("config->sock.bind_addr cannot be empty\n");
      return false;
    }

    if (sock->type != sock_tcp && sock->type != sock_udp) {
      printf("config->sock.type must be \"tcp\" or \"udp\"\n");
      return false;
    }
  }


  {
    /* Validate other section. */
    if (!config->data_dir) {
      printf("config->data_dir cannot be empty\n");
      return false;
    }
  }

  return true;
}
