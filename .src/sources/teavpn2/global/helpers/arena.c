
#include <string.h>
#include <assert.h>
#include <teavpn2/global/helpers/arena.h>

/**
 * Warning:
 * - You must be very very careful in using arena.
 * - Responsibility to manage reuse memory is yours.
 * - It does not have free().
 *
 * YOU HAVE BEEN WARNED!
 */

static char   *ar_addr = NULL;
static size_t ar_size  = 0;
static size_t ar_pos   = 0;


void ar_init(char *ar, size_t ar_size)
{
	ar_addr = ar;
	ar_size = ar_size;
	ar_pos = 0;
}


size_t ar_unused_size()
{
	return ar_size - ar_pos;
}


inline static void *internal_ar_alloc(size_t len)
{
	char *ret = &ar_addr[ar_pos];
	ar_pos += len;

	assert(ar_size > ar_pos);

	return (void *)ret;
}


void *ar_alloc(size_t len)
{
	return internal_ar_alloc(len);
}


void *ar_strdup(const char *str)
{
	char   *ret;
	size_t len = strlen(str);

	ret = internal_ar_alloc(len + 1);
	ret[len] = '\0';

	return memcpy(ret, str, len);
}


void *ar_strndup(const char *str, size_t inlen)
{
	char   *ret;
	size_t len = strnlen(str, inlen);

	ret = internal_ar_alloc(len + 1);
	ret[len] = '\0';

	return memcpy(ret, str, len);
}
