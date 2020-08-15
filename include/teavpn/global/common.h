
#ifndef TEAVPN__GLOBAL__COMMON_H
#define TEAVPN__GLOBAL__COMMON_H

#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

/* =================================================================================== */
/* Socket communication type. */
enum socket_type {
  TEAVPN_SOCK_TCP = 1,
  TEAVPN_SOCK_UDP = 2
};
/* =================================================================================== */



/* =================================================================================== */
/* Authentication type. */
typedef struct _teavpn_auth {
  char        username[64];
  char        password[255];
} teavpn_auth;
/* =================================================================================== */



/* =================================================================================== */
/* Virtual network interface configuration. */
typedef struct _teavpn_net {
  char        *dev;
  char        *inet4;
  char        *inet4_bcmask;
  uint32_t    mtu;
} teavpn_net;

int teavpn_iface_allocate(char *dev);
/* =================================================================================== */





/* =================================================================================== */
/* Client Packet. */

typedef enum {
  CLIENT_PKT_AUTH = 1,
  CLIENT_PKT_DATA,
  CLIENT_PKT_CLOSE,
} cli_pkt_type;

typedef struct __attribute__((__packed__)) _client_packet {
  cli_pkt_type        type;     /* What is being sent? */
  uint16_t            len;      /* The length of data being sent. */
  char                data[1];  /* Struct hack. Its length must be equal to len. */
} client_packet;


#define MIN_CLIENT_PACKET_LENGTH (sizeof(client_packet_type) + sizeof(uint16_t))

/* =================================================================================== */



/* =================================================================================== */
/* Debug and error logger. */
int __teavpn_debug_log(const char *format, ...);
int __teavpn_error_log(const char *format, ...);

#ifndef GLOBAL_LOGGER_C
extern uint8_t __debug_log_level;
#endif

#define debug_log(LEVEL, ...)                \
  ( (__debug_log_level >= ((uint8_t)LEVEL))  \
    ? __teavpn_debug_log(__VA_ARGS__)        \
    : 0                                      \
  )

#define error_log(...) __teavpn_error_log(__VA_ARGS__)
/* =================================================================================== */




/* =================================================================================== */
/* Stack arena. */
void init_stack_arena(void *ptr, size_t length);
void *stack_arena_alloc(register size_t length);
char *stack_strdup(const char *str);
/* =================================================================================== */





#endif
