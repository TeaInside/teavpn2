
#if !defined(__linux__)
#  error This code is supposed to be compiled only for Linux.
#endif

#ifndef TEAVPN2__SERVER__SOCK__TCP__SERVER__LINUX__000_CONTRACTS_H
#define TEAVPN2__SERVER__SOCK__TCP__SERVER__LINUX__000_CONTRACTS_H

inline static void
tvpn_server_tcp_signal_handler(int signal);

inline static void
tvpn_server_tcp_init_channels(tcp_channel *channels, uint16_t n);

inline static void
tvpn_server_tcp_init_channel(tcp_channel *chan);

inline static bool
tvpn_server_tcp_init_socket(server_tcp_state *state);

inline static bool
tvpn_server_tcp_socket_setup(int fd);

inline static void
tvpn_general_init();

inline static void
tvpn_server_tcp_clean_up(server_tcp_state *state);

inline static void
tvpn_server_tcp_close_net_fd(int net_fd);

inline static int
tvpn_server_tcp_event_loop(server_tcp_state *state);

inline static void
tvpn_server_tcp_accept(server_tcp_state *state, struct pollfd *fds,
                       nfds_t *nfds);

inline static bool
tvpn_server_tcp_create_channel(tcp_channel *chan,
                               int fd,
                               const char *remote_addr,
                               uint16_t remote_port,
                               struct sockaddr_in *claddr);

inline static tcp_channel *
tvpn_server_tcp_get_channel(tcp_channel *channels, uint16_t n);

inline static void *
tvpn_server_tcp_thread_worker(void *_chan);

inline static void
tvpn_server_tcp_client_event_loop(tcp_channel *chan);

#endif /* #ifndef TEAVPN2__SERVER__SOCK__TCP__SERVER__LINUX__000_CONTRACTS_H */
