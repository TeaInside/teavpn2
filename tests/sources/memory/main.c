
#include <stdio.h>
#include <assert.h>
#include <string.h>

#include <criterion/criterion.h>
#include <teavpn2/global/memory.h>

Test(memory, contiguous_block_allocation_test)
{
  char arena[4096];
  t_ar_init(arena, sizeof(arena));

  char *a = t_ar_alloc(1024);
  char *b = t_ar_alloc(1024);
  char *c = t_ar_alloc(1024);
  char *d = t_ar_alloc(1024);

  memset(a, 'A', 2048);
  cr_assert(!memcmp(a, b, 1024));

  memset(b, 'B', 2048);
  cr_assert(!memcmp(b, c, 1024));

  memset(c, 'D', 2048);
  cr_assert(!memcmp(c, d, 1024));

  cr_assert(a + 1024 == b);
  cr_assert(b + 1024 == c);
  cr_assert(c + 1024 == d);
}


Test(memory, strdup_test)
{
  char arena[4096];

  /* Initialize arena with 'b'. */
  memset(arena, 'z', sizeof(arena));

  t_ar_init(arena, sizeof(arena));


  /* Simple strdup test. */
  {
    char str[] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    char *ptr  = t_ar_strdup(str);

    cr_assert(!memcmp(ptr, str, sizeof(str)));
  }


  /* strndup test. */
  {
    char str[] = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    size_t shorter_len = (sizeof(str) - 1) - 5;

    char *ptr = t_ar_strndup(str, shorter_len);

    /* Copied string from strndup must be null terminated. */
    cr_assert(ptr[shorter_len] == '\0');

    /* Check untouched memory after strdup and strndup. */
    size_t untouched_len = sizeof(arena) - (&(ptr[shorter_len + 1]) - arena);

    char *cmp_data = (char *)malloc(untouched_len);
    memset(cmp_data, 'z', untouched_len);

    cr_assert(!memcmp(&(ptr[shorter_len + 1]), cmp_data, untouched_len));

    free(cmp_data);
  }
}


#ifdef NEED_MEMCPY_TEST
#if NEED_MEMCPY_TEST

Test(memory, tr_ar_memcpy_test)
{
  char dst[2048];
  char src[2048];

  #define TEST_MEMCPY(N) do {        \
    memset(dst, '\0', sizeof(dst));  \
    memset(src, 'a', N);             \
    t_ar_memcpy(dst, src, N);        \
    cr_assert(!memcmp(dst, src, N)); \
  } while (0)

  /* Must be able to do for aligned and unaligned data. */
  for (int i = 0; i < 2048; ++i) {
    TEST_MEMCPY(i);
  }
}

#endif
#endif
