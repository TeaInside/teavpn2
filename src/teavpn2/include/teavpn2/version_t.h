
#ifndef TEAVPN2__VERSION_T_H
#define TEAVPN2__VERSION_T_H

#include <teavpn2/base.h>


typedef struct _version_t {
	uint8_t		ver;
	uint8_t		patch_lvl;
	uint8_t		sub_lvl;
	char		extra[8];
} version_t;

static_assert(sizeof(version_t) == 3 + 8, "Bad sizeof(version_t)");

static_assert(offsetof(version_t, ver) == 0, "Bad offsetof(version_t, ver)");
static_assert(offsetof(version_t, patch_lvl) == 1,
	      "Bad offsetof(version_t, patch_lvl)");
static_assert(offsetof(version_t, sub_lvl) == 2,
	      "Bad offsetof(version_t, sub_lvl)");
static_assert(offsetof(version_t, extra) == 3,
	      "Bad offsetof(version_t, extra)");

#endif /* #ifndef TEAVPN2__VERSION_T_H */
