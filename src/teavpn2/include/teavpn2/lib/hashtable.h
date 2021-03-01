
#ifndef __TEAVPN2__LIB__HASHTABLE_H
#define __TEAVPN2__LIB__HASHTABLE_H

#include <stdint.h>
#include <stddef.h>


/* Hashtable with open-addressing strategy. */
typedef struct _HashtableOA {
	void		(*hash_f)(const void *data, size_t len); /* Hash func */

	size_t		n;		/* Number of items   */
	size_t		size;		/* Number of buckets */
	Bucket		buckets[];
} HashtableOA;

#endif
