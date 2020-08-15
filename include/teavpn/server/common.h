
#ifndef TEAVPN__SERVER__COMMON_H
#define TEAVPN__SERVER__COMMON_H

#include <arpa/inet.h>
#include <linux/kernel.h>
#include <teavpn/global/common.h>

typedef struct _server_socket {
  char                  *bind_addr;
  uint16_t              bind_port;
  int                   backlog;
  enum socket_type      sock_type;
} server_socket;


typedef struct _teavpn_net {
  char                  *inet4;
  char                  *inet4_bcmask;
  uint16_t              mtu;
} teavpn_net;

typedef struct _server_config {
  char                  *config_file;     /* Config file to be parsed. */
  char                  *data_dir;        /* Data directory. */
  server_socket         socket;           /* Socket communication configuration. */
  teavpn_net            net;              /* Virtual network interface configuration. */
  uint16_t              max_connections;  /* Maximum number of connections. */
} server_config;


typedef struct _server_state {
  int                   *tun_fds;     /* TUN/TAP fds queue. */
  __be32                inet4;        /* Allocated IP for TUN/TAP device. */
  __be32                inet4_bcmask; /* Broadcast mask for TUN/TAP device. */
  server_config         *config;      /* Server config. */
} server_state;

bool teavpn_server_config_parser(char *ini_file, server_config *config);
bool teavpn_server_arg_parser(int argc, char **argv, char **envp, server_config *config);

int teavpn_server_run(server_config *config);

int tun_set_queue(int fd, int enable);
int tun_alloc_mq(char *dev, int queues, int *fds);

int teavpn_server_tcp_run(server_state *config);
int teavpn_server_udp_run(server_state *config);

/* Stack arena. */
void init_stack_arena(void *ptr, size_t length);
void *stack_arena_alloc(register size_t length);
char *stack_strdup(const char *str);

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

#endif
