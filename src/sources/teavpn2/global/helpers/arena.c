
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

static char   *arena_addr = NULL;
static size_t arena_size  = 0;
static size_t arena_pos   = 0;


void arena_init(char *arena, size_t arena_size)
{
	arena_addr = arena;
	arena_size = arena_size;
	arena_pos = 0;
}


size_t arena_unused_size()
{
	return arena_size - arena_pos;
}


inline static void *internal_arena_alloc(size_t len)
{
	char *ret = &arena_addr[arena_pos];
	arena_pos += len;

	assert(arena_size > arena_pos);

	return (void *)ret;
}


void *arena_alloc(size_t len)
{
	return internal_arena_alloc(len);
}


void *arena_strdup(const char *str)
{
	char   *ret;
	size_t len = strlen(str);

	ret = internal_arena_alloc(len + 1);
	ret[len] = '\0';

	return memcpy(ret, str, len);
}


void *arena_strndup(const char *str, size_t inlen)
{
	char   *ret;
	size_t len = strnlen(str, inlen);

	ret = internal_arena_alloc(len + 1);
	ret[len] = '\0';

	return memcpy(ret, str, len);
}
