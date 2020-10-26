
#include <string.h>
#include <assert.h>


#include <teavpn2/global/helpers/memory.h>


static void    *t_arena      = NULL;
static size_t  t_arena_len   = 0;
static size_t  t_arena_pos   = 0;


void
t_ar_init(register void *ptr, register size_t len)
{
  t_arena     = ptr;
  t_arena_len = len;
}


void *
t_ar_alloc(register size_t len)
{
  register char *ret  = &(((char *)t_arena)[t_arena_pos]);
  t_arena_pos        += len;

  /* Check if run out of arena. */
  assert(t_arena_pos <= t_arena_len);

  return (void *)ret;
}


char *
t_ar_strdup(register const char *str)
{
  register size_t len   = strlen(str);
  register char   *ret  = &(((char *)t_arena)[t_arena_pos]);
  t_arena_pos          += len + 1;

  t_ar_memcpy(ret, str, len);
  ret[len] = '\0';

  return ret;
}


char *
t_ar_strndup(register const char *str, register size_t tlen)
{
  register size_t len  = strlen(str);
  register char   *ret = &(((char *)t_arena)[t_arena_pos]);

  tlen = (len < tlen) ? len : tlen;

  t_arena_pos += tlen + 1;
  t_ar_memcpy(ret, str, tlen);
  ret[tlen] = '\0';

  return ret;
}
