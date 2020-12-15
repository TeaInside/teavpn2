
#ifndef TEAVPN2__SERVER__VPN__LINUX_INLINE_CONTRACTS_H
#define TEAVPN2__SERVER__VPN__LINUX_INLINE_CONTRACTS_H

inline static bool
tsrv_init_tun_fd_tcp(tcp_state *state);

inline static int
tsrv_run_tcp(srv_cfg *cfg);

inline static void
tsrv_clean_up_tcp(tcp_state *state);

inline static bool
tsrv_init_sock_tcp(tcp_state *state);

inline static bool
tsrv_init_pipe_tcp(tcp_state *state);

inline static void
tsrv_init_channel_tcp(tcp_channel *chan, const uint16_t n);

#endif /* #ifndef TEAVPN2__SERVER__VPN__LINUX_INLINE_CONTRACTS_H */
