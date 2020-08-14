
#ifndef __TEAVPN__SERVER__CONFIG_H
#define __TEAVPN__SERVER__CONFIG_H

typedef struct {
  char inet4[32];
  char inet4_bc[32];

} teavpn_srv_inet4;

enum teavpn_iface_type {
  TEAVPN_INET4,
  TEAVPN_INET6
};

typedef struct {
  /* Configuration file. */
  char config_file[255];

  /* Data directory. */
  char data_dir[255];

  /* Network interface. */
  enum iface_type;
  union {
    teavpn_srv_inet4 inet4;
    teavpn_srv_inet6 inet6;
  } iface;
  
  /* Socket bind address. */
  struct {
    char bind_addr[128];
    uint16_t bind_port;
    int backlog;
  } sock;

  /* mstate pointer. */
  void *mstate;
} teavpn_srv_cfg;

#endif
