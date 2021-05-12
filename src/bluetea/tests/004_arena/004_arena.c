// SPDX-License-Identifier: GPL-2.0
/*
 *  src/bluetea/tests/004_arena/004_arena.c
 *
 *  Test case for arena
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#include <bluetea/teatest.h>
#include <bluetea/lib/arena.h>


static TEATEST(004_arena, init_arena)
{
	TQ_START;
	alignas(16) char arena[0x1000];

	/* Unaligned pointer must fail */
	TQ_ASSERT(ar_init(arena + 1, sizeof(arena)) == -EINVAL);
	TQ_ASSERT(ar_capacity() == 0);

	/* Size not multiple of 16 must fail */
	TQ_ASSERT(ar_init(arena, 15) == -EINVAL);
	TQ_ASSERT(ar_capacity() == 0);
	TQ_ASSERT(ar_init(arena, 17) == -EINVAL);
	TQ_ASSERT(ar_capacity() == 0);


	TQ_ASSERT(ar_init(arena, sizeof(arena)) == 0);
	TQ_ASSERT(ar_capacity() == sizeof(arena));

	TQ_RETURN;
}


static TEATEST(004_arena, allocate_arena)
{
	TQ_START;
	void *ptr = NULL;
	uintptr_t uptr = 0;
	alignas(16) char arena[0x1000];

	TQ_ASSERT(ar_init(arena, sizeof(arena)) == 0);

	TQ_VOID(ptr = ar_alloc(32));
	TQ_VOID(uptr = (uintptr_t)ptr);
	TQ_ASSERT(ptr != NULL);
	/* Must be 16 byte aligned */
	TQ_ASSERT((uptr & 0xfull) == 0);
	TQ_ASSERT(ar_capacity() == (sizeof(arena) - 32));


	for (size_t i = 2; i <= 30; i++) {
		ptr  = ar_alloc(32);
		uptr = (uintptr_t)ptr;
		TQ_ASSERT_S(ptr != NULL);
		TQ_VOID(uptr = (uintptr_t)ptr);
		TQ_ASSERT_S((uptr & 0xfull) == 0);
		TQ_ASSERT_S(ar_capacity() == (sizeof(arena) - (32 * i)));
	}


	/*
	 * Must still take 32 bytes eventhough it allocates 30 or 31
	 * It is just for alignment purpose.
	 */
	for (size_t i = 31; i <= 60; i++) {
		ptr  = ar_alloc((i % 2) ? 30 : 31);
		uptr = (uintptr_t)ptr;
		TQ_ASSERT_S(ptr != NULL);
		TQ_VOID(uptr = (uintptr_t)ptr);
		TQ_ASSERT_S((uptr & 0xfull) == 0);
		TQ_ASSERT_S(ar_capacity() == (sizeof(arena) - (32 * i)));
	}

	TQ_RETURN;
}


static TEATEST(004_arena, enomem)
{
	TQ_START;
	int err = 0;
	void *ptr = NULL;
	uintptr_t uptr = 0;
	alignas(16) char arena[1024];

	TQ_ASSERT(ar_init(arena, sizeof(arena)) == 0);
	TQ_ASSERT(ar_capacity() == sizeof(arena));

	TQ_VOID(ptr = ar_alloc(512));
	TQ_ASSERT_S(ptr != NULL);
	TQ_VOID(uptr = (uintptr_t)ptr);
	TQ_ASSERT_S((uptr & 0xfull) == 0);
	TQ_ASSERT(ar_capacity() == 512);

	TQ_VOID(ptr = ar_alloc(512));
	TQ_ASSERT_S(ptr != NULL);
	TQ_VOID(uptr = (uintptr_t)ptr);
	TQ_ASSERT_S((uptr & 0xfull) == 0);
	TQ_ASSERT(ar_capacity() == 0);

	TQ_VOID(ptr = ar_alloc(512));
	TQ_VOID(err = errno);
	TQ_ASSERT_S(ptr == NULL);
	TQ_ASSERT_S(err == ENOMEM);
	TQ_ASSERT(ar_capacity() == 0);

	TQ_VOID(ptr = ar_alloc(1));
	TQ_VOID(err = errno);
	TQ_ASSERT_S(ptr == NULL);
	TQ_ASSERT_S(err == ENOMEM);
	TQ_ASSERT(ar_capacity() == 0);

	TQ_RETURN;
}


static TEATEST(004_arena, string_dup)
{
	TQ_START;
	char *str = NULL;
	uintptr_t uptr = 0;
	alignas(16) char arena[1024];

	TQ_ASSERT(ar_init(arena, sizeof(arena)) == 0);
	TQ_ASSERT(ar_capacity() == sizeof(arena));

	TQ_ASSERT(str = ar_strdup("Hello World!"));
	TQ_VOID(uptr = (uintptr_t)str);
	TQ_ASSERT_S((uptr & 0xfull) == 0);
	TQ_ASSERT(!memcmp(str, "Hello World!", sizeof("Hello World!")));
	TQ_ASSERT(ar_capacity() == (1024 - (16 * 1)));


	/* strndup */
	TQ_ASSERT(str = ar_strndup("Hello World!", 666));
	TQ_VOID(uptr = (uintptr_t)str);
	TQ_ASSERT_S((uptr & 0xfull) == 0);
	TQ_ASSERT(!memcmp(str, "Hello World!", sizeof("Hello World!")));
	TQ_ASSERT(ar_capacity() == (1024 - (16 * 2)));


	TQ_ASSERT(str = ar_strndup("Hello World!", 5));
	TQ_VOID(uptr = (uintptr_t)str);
	TQ_ASSERT_S((uptr & 0xfull) == 0);
	TQ_ASSERT(!memcmp(str, "Hello", sizeof("Hello")));
	TQ_ASSERT(ar_capacity() == (1024 - (16 * 3)));


	TQ_ASSERT(str = ar_strndup("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 33));
	TQ_VOID(uptr = (uintptr_t)str);
	TQ_ASSERT_S((uptr & 0xfull) == 0);
	TQ_ASSERT(!memcmp(str, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", sizeof("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")));
	TQ_ASSERT(ar_capacity() == (1024 - (16 * 3) - (16 * 3)));

	TQ_ASSERT(ar_init(arena, 32) == 0);
	TQ_ASSERT(ar_capacity() == 32);
	TQ_ASSERT(ar_strndup("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 32) == NULL);
	TQ_ASSERT(ar_capacity() == 32);
	TQ_ASSERT(!memcmp(ar_strndup("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 31), "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 32));
	TQ_ASSERT(ar_capacity() == 0);

	TQ_RETURN;
}


extern const test_entry_t test_entry_arr[];
const test_entry_t test_entry_arr[] = {
	FN_TEATEST(004_arena, init_arena),
	FN_TEATEST(004_arena, allocate_arena),
	FN_TEATEST(004_arena, enomem),
	FN_TEATEST(004_arena, string_dup),
	NULL
};
