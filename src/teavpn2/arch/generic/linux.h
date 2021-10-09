// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021  Ammar Faizi
 */

#ifndef TEAVPN2__ARCH__GENERIC__LINUX_H
#define TEAVPN2__ARCH__GENERIC__LINUX_H

#include <errno.h>
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/syscall.h>

static inline int __sys_epoll_wait(int epfd, struct epoll_event *events,
				   int maxevents, int timeout)
{
	int ret;
	ret = epoll_wait(epfd, events, maxevents, timeout);
	return unlikely(ret < 0) ? -errno : ret;
}

static inline ssize_t __sys_read(int fd, void *buf, size_t len)
{
	ssize_t ret;
	ret = read(fd, buf, len);
	return unlikely(ret < 0) ? (ssize_t) -errno : ret;
}

static inline ssize_t __sys_write(int fd, const void *buf, size_t len)
{
	ssize_t ret;
	ret = write(fd, buf, len);
	return unlikely(ret < 0) ? (ssize_t) -errno : ret;
}

static inline ssize_t __sys_recvfrom(int sockfd, void *buf, size_t len,
				     int flags, struct sockaddr *src_addr,
				     socklen_t *addrlen)
{
	ssize_t ret;
	ret = recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
	return unlikely(ret < 0) ? (ssize_t) -errno : ret;
}

static inline ssize_t __sys_sendto(int sockfd, const void *buf, size_t len,
				   int flags, const struct sockaddr *dest_addr,
				   socklen_t addrlen)
{
	ssize_t ret;
	ret = sendto(sockfd, buf, len, flags, dest_addr, addrlen);
	return unlikely(ret < 0) ? (ssize_t) -errno : ret;
}

#endif /* #ifndef TEAVPN2__ARCH__GENERIC__LINUX_H */
