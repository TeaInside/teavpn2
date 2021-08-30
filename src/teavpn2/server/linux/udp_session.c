// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021  Ammar Faizi
 */

#include <unistd.h>
#include <sys/epoll.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <teavpn2/server/common.h>
#include <teavpn2/server/linux/udp.h>


static __always_inline struct udp_map_bucket *addr_to_bkt(
	struct udp_map_bucket (*sess_map)[0x100u],
	uint32_t addr
)
{
	size_t idx1, idx2;
	idx1 = (addr >> 0u) & 0xffu;
	idx2 = (addr >> 8u) & 0xffu;
	return &(sess_map[idx1][idx2]);
}


struct udp_sess *map_find_udp_sess(struct srv_udp_state *state, uint32_t addr,
				   uint16_t port)
	__acquires(&state->sess_map_lock)
	__releases(&state->sess_map_lock)
{
	struct udp_map_bucket *bkt;
	struct udp_sess *ret;

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


struct udp_sess *map_insert_udp_sess(struct srv_udp_state *state, uint32_t addr,
				     uint16_t port, struct udp_sess *cur_sess)
	__acquires(&state->sess_map_lock)
	__releases(&state->sess_map_lock)
{
	struct udp_sess *ret = cur_sess;
	struct udp_map_bucket *bkt, *new_bkt;

	bkt = addr_to_bkt(state->sess_map, addr);
	mutex_lock(&state->sess_map_lock);
	if (!bkt->sess) {
		bkt->sess = cur_sess;
		/* If first entry is empty, there should be no next! */
		if (WARN_ON(bkt->next != NULL))
			bkt->next = NULL;
		goto out;
	}

	new_bkt = malloc(sizeof(*new_bkt));
	if (unlikely(!new_bkt)) {
		ret = NULL;
		goto out;
	}

	new_bkt->next = NULL;
	new_bkt->sess = cur_sess;

	while (bkt->next)
		bkt = bkt->next;

	bkt->next = new_bkt;
out:
	mutex_unlock(&state->sess_map_lock);
	return ret;
}


struct udp_sess *get_udp_sess(struct srv_udp_state *state, uint32_t addr,
			      uint16_t port)
	__acquires(&state->sess_stk_lock)
	__releases(&state->sess_stk_lock)
{
	int err = 0;
	uint16_t idx;
	int32_t stk_ret;
	struct udp_sess *cur_sess, *ret = NULL;

	mutex_lock(&state->sess_stk_lock);
	stk_ret = bt_stack_pop(&state->sess_stk);
	if (unlikely(stk_ret == -1)) {
		pr_err("Client slot is full, cannot accept more client!");
		err = EAGAIN;
		goto out;
	}

	idx = (uint16_t)stk_ret;
	cur_sess = &state->sess[idx];
	cur_sess->src_addr = addr;
	cur_sess->src_port = port;
	ret = map_insert_udp_sess(state, addr, port, cur_sess);
	if (unlikely(!ret)) {
		BUG_ON(bt_stack_push(&state->sess_stk, idx) == -1);
		pr_err("Cannot allocate memory on map_insert_udp_sess()!");
		err = ENOMEM;
		goto out;
	}

	addr = htonl(addr);
	WARN_ON(!inet_ntop(AF_INET, &addr, cur_sess->str_addr,
			   sizeof(cur_sess->str_addr)));
out:
	mutex_unlock(&state->sess_stk_lock);
	errno = err;
	return ret;
}


// static inline struct udp_map_bucket *addr_to_udp_map_bucket(
// 	struct udp_map_bucket (*sess_map)[0x100], uint32_t addr)
// {
// 	size_t idx1, idx2;
// 	idx1 = (addr >> 0u) & 0xffu;
// 	idx2 = (addr >> 8u) & 0xffu;
// 	return &(sess_map[idx1][idx2]);
// }


// struct udp_sess *map_find_udp_sess(struct srv_udp_state *state, uint32_t addr,
// 				   uint16_t port)
// {
// 	struct udp_sess *ret;
// 	struct udp_map_bucket *bkt;

// 	bkt = addr_to_udp_map_bucket(state->sess_map, addr);
// 	do {
// 		ret = bkt->sess;
// 		if (ret && (ret->src_addr == addr) && (ret->src_port == port))
// 			return ret;

// 		bkt = bkt->next;
// 	} while (bkt != NULL);

// 	return NULL;
// }


// struct udp_sess *map_insert_udp_sess(struct srv_udp_state *state, uint32_t addr,
// 				     uint16_t port, struct udp_sess *cur_sess)
// {
// 	size_t idx1, idx2;
// 	struct udp_map_bucket *bkt, *new_bkt;

// 	bkt = addr_to_udp_map_bucket(state->sess_map, addr);
// 	if (bkt->sess == NULL) {
// 		bkt->sess = cur_sess;
// 		goto out;
// 	}

// 	new_bkt = malloc(sizeof(*new_bkt));
// 	if (unlikely(!new_bkt))
// 		return NULL;

// 	while (bkt->next)
// 		bkt = bkt->next;

// 	new_bkt->next = NULL;
// 	new_bkt->sess = cur_sess;
// 	bkt->next = new_bkt;
// out:
// 	WARN_ON(cur_sess->src_addr != addr);
// 	WARN_ON(cur_sess->src_port != port);
// 	return cur_sess;
// }


// int map_delete_udp_sess()
// {
// 	/* TODO: Remove the session from map. */
// 	return 0;
// }


// struct udp_sess *get_udp_sess(struct srv_udp_state *state, uint32_t addr,
// 			      uint16_t port)
// 	__acquires(&state->sess_stk_lock)
// 	__releases(&state->sess_stk_lock)
// {
// #if 0
// 	uint16_t idx;
// 	int32_t stk_ret;
// 	struct udp_sess *cur_sess;

// 	pthread_mutex_lock(&state->sess_stk_lock);
// 	stk_ret = bt_stack_pop(&state->sess_stk);
// 	if (unlikely(stk_ret == -1)) {
// 		pthread_mutex_unlock(&state->sess_stk_lock);
// 		pr_err("Client slot is full, cannot accept more client!");
// 		errno = EAGAIN;
// 		return NULL;
// 	}

// 	idx = (uint16_t)stk_ret;
// 	cur_sess = &state->sess[idx];
// 	cur_sess->src_addr = addr;
// 	cur_sess->src_port = port;
// 	if (unlikely(!map_insert_udp_sess(state->sess_map, addr, port, cur_sess))) {
// 		BUG_ON(bt_stack_push(&state->sess_stk, idx) == -1);
// 		pthread_mutex_unlock(&state->sess_stk_lock);
// 		pr_err("Cannot allocate memory on get_sess()!");
// 		errno = ENOMEM;
// 		return NULL;
// 	}

// 	pthread_mutex_unlock(&state->sess_stk_lock);
// 	return cur_sess;
// #endif
// }


// int put_udp_sess(struct srv_udp_state *state, struct udp_sess *sess)
// 	__acquires(&state->sess_stk_lock)
// 	__releases(&state->sess_stk_lock)
// {
// #if 0
// 	int ret = 0;
// 	uint16_t idx = sess->idx;
// 	uint32_t addr = sess->src_addr;
// 	uint16_t port = sess->src_port;

// 	pthread_mutex_lock(&state->sess_stk_lock);
// 	reset_udp_session(sess, idx);
// 	if (WARN_ON(bt_stack_push(&state->sess_stk, idx) == -1))
// 		ret = -EINVAL;
// 	// map_delete_udp_sess(state, addr, port);
// 	pthread_mutex_unlock(&state->sess_stk_lock);
// 	return ret;
// #endif
// }
