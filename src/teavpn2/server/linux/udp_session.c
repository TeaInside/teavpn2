// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021  Ammar Faizi
 */

#include <unistd.h>
#include <sys/epoll.h>
#include <teavpn2/server/linux/udp.h>


static __always_inline struct udp_map_bucket *addr_to_bkt(
	struct udp_map_bucket (*sess_map)[0x100u], uint32_t addr)
{
	size_t idx1, idx2;
	idx1 = (addr >> 0u) & 0xffu;
	idx2 = (addr >> 8u) & 0xffu;
	return &(sess_map[idx1][idx2]);
}


struct udp_sess *create_udp_sess(struct srv_udp_state *state, uint32_t addr,
				 uint16_t port)
	__acquires(&state->sess_map_lock)
	__releases(&state->sess_map_lock)
{
	struct udp_sess *sess, *ret = NULL;

	mutex_lock(&state->sess_stk_lock);
out:
	mutex_unlock(&state->sess_map_lock);
	return ret;
}


struct udp_sess *lookup_udp_sess(struct srv_udp_state *state, uint32_t addr,
				 uint16_t port)
	__acquires(&state->sess_map_lock)
	__releases(&state->sess_map_lock)
{
	struct udp_sess *ret;
	struct udp_map_bucket *bkt;

	bkt = addr_to_bkt(state->sess_map, addr);
	mutex_lock(&state->sess_map_lock);
	do {
		ret = bkt->sess;
		if (ret) {
			if ((ret->src_addr == addr) && (ret->src_port == port))
				goto out;
			else
				ret = NULL;
		}

		bkt = bkt->next;
	} while (bkt);
out:
	mutex_unlock(&state->sess_map_lock);
	return ret;
}
