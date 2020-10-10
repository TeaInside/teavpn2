
#ifndef TEAVPN2__GLOBAL__TYPES_H
#define TEAVPN2__GLOBAL__TYPES_H

#include <stdbool.h>

#if defined(__linux__)
#include <linux/types.h>
#else
typedef unsigned int __be32;
#endif

#endif
