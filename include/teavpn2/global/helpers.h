
#ifndef __TEAVPN__GLOBAL__HELPERS_H
#define __TEAVPN__GLOBAL__HELPERS_H

char *escape_sh(
  register char *cmd, /* arena */
  register char *str, /* string to be escaped */
  register size_t l   /* string length */
);

#endif
