
#ifndef TEAVPN2__CLIENT__SOCK__TCP__CLIENT__LINUX_H
#  error This file must only be included from   \
         teavpn2/client/sock/tcp/client/linux.h
#endif

#ifndef TEAVPN2__CLIENT__SOCK__TCP__CLIENT__LINUX__AUTH_H
#define TEAVPN2__CLIENT__SOCK__TCP__CLIENT__LINUX__AUTH_H


/**
 * @param  client_tcp_state * __restrict__ state
 * @return bool
 */
inline static bool
tvpn_client_tcp_auth(client_tcp_state * __restrict__ state)
{
  register client_cfg   *config   = state->config;
  register int          net_fd    = state->net_fd;
  register cl_pkt       *cli_pkt  = (cl_pkt *)state->recv_buff;
  register cl_pkt_auth  *auth_pkt = (cl_pkt_auth *)cli_pkt->data;
  register size_t       pkt_data_size;
  register size_t       data_size;
  register char         *wptr;
  register ssize_t      ret;
  register uint8_t      ul; /* Username length. */
  register uint8_t      pl; /* Password length. */

  /* ======================================================= */
  ul   = strnlen(config->auth.username, 254);
  pl   = strnlen(config->auth.password, 254);
  wptr = auth_pkt->data;

  strncpy(wptr, config->auth.username, ul);
  wptr[ul]  = '\0';
  wptr     += ul + 1;

  strncpy(wptr, config->auth.password, pl);
  wptr[pl]  = '\0';

  auth_pkt->username_len = ul;
  auth_pkt->password_len = pl;
  /* ======================================================= */

  pkt_data_size = OFFSETOF(cl_pkt_auth, data) + (ul + 1) + (pl + 1);
  data_size     = CL_IDENT_SZ + pkt_data_size;

  cli_pkt->type = CL_PKT_AUTH;
  cli_pkt->len  = htons(pkt_data_size);

  ret = send(net_fd, cli_pkt, data_size, MSG_DONTWAIT);

  if (ret < 0) {
    state->stop = true;
    debug_log(0, "Error send(): %s", strerror(errno));
    return false;
  }

  state->send_count++;
  debug_log(5, "send() %d bytes", ret);

  return true;
}

#endif /* #ifndef TEAVPN2__CLIENT__SOCK__TCP__CLIENT__LINUX__AUTH_H */
