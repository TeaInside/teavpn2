



struct srv_tcp_state {
	int		tun_fd;
	int		net_fd;
	int		epl_fd;
#ifdef TEAVPN_DEBUG
	struct {
		uint32_t	read_c;
		uint32_t	write_c;
	} ctr;
#endif
};
