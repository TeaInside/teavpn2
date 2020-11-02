
#include <string.h>
#include <assert.h>


#include <teavpn2/global/helpers/memory.h>


static void    *t_arena      = NULL;
static size_t  t_arena_len   = 0;
static size_t  t_arena_pos   = 0;

/**
 * @param void   *ptr
 * @param size_t len
 * @return void
 */
void
t_ar_init(void *ptr, size_t len)
{
  t_arena     = ptr;
  t_arena_len = len;
}


/**
 * @param size_t len
 * @return void *
 */
inline static void *
_internal_t_ar_alloc(size_t len)
{
  char *ret    = &(((char *)t_arena)[t_arena_pos]);

  __sync_synchronize();
  t_arena_pos += len;

  /* Check if run out of arena. */
  assert(t_arena_pos <= t_arena_len);

  return (void *)ret;
}


/**
 * @param size_t len
 * @return void *
 */
void *
t_ar_alloc(size_t len)
{
  return _internal_t_ar_alloc(len);
}


/**
 * @param const char *str
 * @return char *
 */
char *
t_ar_strdup(const char *str)
{
  size_t len   = strlen(str);
  char   *ret  = &(((char *)t_arena)[t_arena_pos]);

  __sync_synchronize();
  t_arena_pos += len + 1;
  t_ar_memcpy(ret, str, len);
  ret[len] = '\0';

  return ret;
}


/**
 * @param const char *str
 * @param size_t     tlen
 * @return char *
 */
char *
t_ar_strndup(const char *str, size_t tlen)
{
  size_t len  = strlen(str);
  char   *ret = &(((char *)t_arena)[t_arena_pos]);

  tlen = (len < tlen) ? len : tlen;

  __sync_synchronize();
  t_arena_pos += tlen + 1;
  t_ar_memcpy(ret, str, tlen);
  ret[tlen] = '\0';

  return ret;
}
