
#ifndef TEAVPN2__GLOBAL__TYPES_H
#define TEAVPN2__GLOBAL__TYPES_H


#include <stdint.h>
#include <stdbool.h>

#if defined(__linux__)
#  include <arpa/inet.h>
#  include <linux/types.h>
#else

typedef uint64_t __be64;
typedef uint32_t __be32;
typedef uint16_t __be16;

#endif


#ifndef INET_ADDRSTRLEN
#  define IPV4L (sizeof("xxx.xxx.xxx.xxx"))
#else
#  define IPV4L (INET_ADDRSTRLEN)
#endif


#ifndef INET6_ADDRSTRLEN
#  define IPV6L (sizeof("xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxx.xxx.xxx.xxx"))
#else
#  define IPV6L (INET6_ADDRSTRLEN)
#endif


typedef enum __attribute__((packed)) {
  SOCK_TCP = 1,
  SOCK_UDP = 2
} sock_type;


#endif
