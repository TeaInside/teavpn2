
#if !defined(__linux__)
#  error This code is supposed to be compiled only for Linux.
#endif

#ifndef TEAVPN2__SERVER__SOCK__TCP__SERVER__LINUX_H
#define TEAVPN2__SERVER__SOCK__TCP__SERVER__LINUX_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <poll.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <pthread.h>

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/tcp.h>

#include "linux/000_contracts.h"

#include "linux/init.h"
#include "linux/iface.h"
#include "linux/clean_up.h"
#include "linux/evl_master.h"
#include "linux/evl_client.h"

#endif /* #ifndef TEAVPN2__SERVER__SOCK__TCP__SERVER__LINUX_H */
