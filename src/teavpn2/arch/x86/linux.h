// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021  Ammar Faizi
 */

#ifndef TEAVPN2__ARCH__X86__LINUX_H
#define TEAVPN2__ARCH__X86__LINUX_H

#include <stdint.h>
#include <stddef.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/syscall.h>

#define ASM_ABR_RW 0xffffffff

static inline int __sys_epoll_wait(int epfd, struct epoll_event *events,
				   int maxevents, int timeout)
{
	long rax;
	register int r10 __asm__("r10") = timeout;

	__asm__ volatile(
		"syscall"
		: "=a"(rax),		/* %rax */
		  "=m"(*(char (*)[ASM_ABR_RW])events)
		: "a"(__NR_epoll_wait),	/* %rax */
		  "D"(epfd),		/* %rdi */
		  "S"(events),		/* %rsi */
		  "d"(maxevents),	/* %rdx */
		  "r"(r10)		/* %r10 */
		: "rcx", "r11"
	);
	return (int) rax;
}

static inline ssize_t __sys_read(int fd, void *buf, size_t len)
{
	ssize_t rax;

	__asm__ volatile(
		"syscall"
		: "=a"(rax),		/* %rax */
		  "=m"(*(char (*)[ASM_ABR_RW])buf)
		: "a"(__NR_read),	/* %rax */
		  "D"(fd),		/* %rdi */
		  "S"(buf),		/* %rsi */
		  "d"(len)		/* %rdx */
		: "rcx", "r11"
	);
	return rax;
}

static inline ssize_t __sys_write(int fd, const void *buf, size_t len)
{
	ssize_t rax;

	__asm__ volatile(
		"syscall"
		: "=a"(rax)		/* %rax */
		: "a"(__NR_write),	/* %rax */
		  "D"(fd),		/* %rdi */
		  "S"(buf),		/* %rsi */
		  "d"(len),		/* %rdx */
		  "m"(*(const char (*)[ASM_ABR_RW])buf)
		: "rcx", "r11"
	);
	return rax;
}

static inline ssize_t __sys_recvfrom(int sockfd, void *buf, size_t len,
				     int flags, struct sockaddr *src_addr,
				     socklen_t *addrlen)
{
	ssize_t rax;
	register int r10 __asm__("r10") = flags;
	register struct sockaddr *r8 __asm__("r8") = src_addr;
	register socklen_t *r9 __asm__("r9") = addrlen;

	__asm__ volatile(
		"syscall"
		: "=a"(rax),		/* %rax */
		  "=m"(*(char (*)[ASM_ABR_RW])buf),
		  "+m"(*(char (*)[ASM_ABR_RW])src_addr),
		  "+m"(*addrlen)
		: "a"(__NR_recvfrom),	/* %rax */
		  "D"(sockfd),		/* %rdi */
		  "S"(buf),		/* %rsi */
		  "d"(len),		/* %rdx */
		  "r"(r10),		/* %r10 */
		  "r"(r8),		/* %r8  */
		  "r"(r9)		/* %r9  */
		: "rcx", "r11"
	);
	return rax;
}

static inline ssize_t __sys_sendto(int sockfd, const void *buf, size_t len,
				   int flags, const struct sockaddr *dest_addr,
				   socklen_t addrlen)
{
	ssize_t rax;
	register int r10 __asm__("r10") = flags;
	register const struct sockaddr *r8 __asm__("r8") = dest_addr;
	register socklen_t r9 __asm__("r9") = addrlen;

	__asm__ volatile(
		"syscall"
		: "=a"(rax)		/* %rax */
		: "a"(__NR_sendto),	/* %rax */
		  "D"(sockfd),		/* %rdi */
		  "S"(buf),		/* %rsi */
		  "d"(len),		/* %rdx */
		  "r"(r10),		/* %r10 */
		  "r"(r8),		/* %r8  */
		  "r"(r9),		/* %r9  */
		  "m"(*(const char (*)[ASM_ABR_RW])buf),
		  "m"(*(const char (*)[ASM_ABR_RW])dest_addr)
		: "rcx", "r11"
	);
	return rax;
}

#endif /* #ifndef TEAVPN2__ARCH__X86__LINUX_H */
