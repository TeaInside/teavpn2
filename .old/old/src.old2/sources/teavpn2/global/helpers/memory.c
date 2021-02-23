
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <teavpn2/global/helpers/memory.h>


static void    *arena_ptr = (void *)0;
static size_t  arena_size = 0;
static size_t  arena_pos  = 0;

/**
 * @param void   *_arena_ptr
 * @param size_t _arena_size
 * @return void
 */
void
ar_init(void *_arena_ptr, size_t _arena_size)
{
  arena_ptr  = _arena_ptr;
  arena_size = _arena_size;
  arena_pos  = 0;
}

/**
 * @param size_t len
 * @return void *
 */
static inline void *
_internal_ar_alloc(size_t len)
{
  char   *ret;
  size_t _arena_pos = arena_pos;

  ret         = &(((char *)arena_ptr)[_arena_pos]);
  _arena_pos += len;

  /* Check if run out of arena. */
  assert(_arena_pos <= arena_size);

  arena_pos   = _arena_pos;

  return (void *)ret;
}

/**
 * @param size_t len
 * @return void *
 */
void *
ar_alloc(size_t len)
{
  return _internal_ar_alloc(len);
}

/**
 * @param const char *str
 * @return char *
 */
char *
ar_strdup(const char *str)
{
  size_t len  = strlen(str);
  char   *ret = _internal_ar_alloc(len + 1);

  ar_memcpy(ret, str, len);
  ret[len] = '\0';

  return ret;
}

/**
 * @param const char *str
 * @param size_t     max_len
 * @return char *
 */
char *
ar_strndup(const char *str, size_t maxlen)
{
  size_t len      = strnlen(str, maxlen);
  size_t fix_len;
  char   *ret;

  if (len < maxlen) {
    fix_len = len;
  } else {
    fix_len = maxlen;
  }

  ret = _internal_ar_alloc(fix_len + 1);

  ar_memcpy(ret, str, fix_len);
  ret[len] = '\0';

  return ret;
}

/**
 * @param size_t n
 * return void *
 */
void *
ar_malloc32(size_t n)
{
  size_t add_siz = 31 + sizeof(void *);
  void   *heap   = malloc(n + add_siz);
  if (NULL == heap) {
    return NULL;
  }

  void *user_ptr = (void *)(
    (((uintptr_t)heap) + add_siz) & (~(uintptr_t)0b11111ul)
  );
  ((void **)user_ptr)[-1] = heap;

  return user_ptr;
}

/**
 * @param void *ptr
 * return void
 */
void
ar_free32(void *ptr)
{
  if (!ptr) return;
  free(((void **)ptr)[-1]);
}
