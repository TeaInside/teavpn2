
#ifndef TEAVPN__GLOBAL__HELPERS_H
#define TEAVPN__GLOBAL__HELPERS_H

char *escape_sh(
  register char *cmd, /* arena */
  register char *str, /* string to be escaped */
  register size_t l   /* string length */
);

#endif
