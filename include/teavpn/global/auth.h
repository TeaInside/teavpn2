
#ifndef __TEAVPN__GLOBAL__AUTH_H
#define __TEAVPN__GLOBAL__AUTH_H

typedef struct _teavpn_auth teavpn_auth;

struct _teavpn_auth {
  char username[64];
  char password[64];
};

#endif
