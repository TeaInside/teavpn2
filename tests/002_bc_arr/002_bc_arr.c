// SPDX-License-Identifier: GPL-2.0-only
/*
 *  tests/001_string/001_string.c
 *
 *  Test case for broadcast array
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#include <criterion/criterion.h>

#define BC_ARR_TEST
#include <teavpn2/server/bc_arr.h>


Test(bc_arr, init_bc_arr_must_be_empty)
{
	struct bc_arr bc;

	cr_assert_eq(bc_arr_init(&bc, 100), 0, "bc_arr_init");
	cr_assert_eq(bc_arr_count(&bc), 0, "bc_arr_count");
	cr_assert_eq(bc.max, 100, "Wrong max");

	bc_arr_destroy(&bc);
}

Test(bc_arr, after_insert_then_the_count_increased)
{
	struct bc_arr bc;
	uint16_t cmp[] = {4, 3, 2, 1, 0};

	cr_assert_eq(bc_arr_init(&bc, 100), 0, "bc_arr_init");

	cr_assert_eq(bc_arr_insert(&bc, 4), 0, "bc_arr_insert");
	cr_assert_eq(bc_arr_insert(&bc, 3), 1, "bc_arr_insert");
	cr_assert_eq(bc_arr_insert(&bc, 2), 2, "bc_arr_insert");
	cr_assert_eq(bc_arr_insert(&bc, 1), 3, "bc_arr_insert");
	cr_assert_eq(bc_arr_insert(&bc, 0), 4, "bc_arr_insert");

	cr_assert_eq(bc_arr_count(&bc), 5, "bc_arr_count");

	cr_assert_eq(memcmp(&cmp, bc.arr, sizeof(cmp)), 0, "memcmp");

	bc_arr_destroy(&bc);
}


Test(bc_arr, efficient_remove)
{
	struct bc_arr bc;
	uint16_t cmp0[] = {[0]=4, [1]=3, [2]=2, [3]=1, [4]=0}; // remove [1]
	uint16_t cmp1[] = {[0]=4, [1]=0, [2]=2, [3]=1}; // remove [0]
	uint16_t cmp2[] = {[0]=1, [1]=0, [2]=2}; // remove [2]
	uint16_t cmp3[] = {[0]=1, [1]=0}; // remove [0]
	uint16_t cmp4[] = {[0]=0};

	cr_assert_eq(bc_arr_init(&bc, 100), 0, "bc_arr_init");
	for (uint16_t i = 0; i < 5; i++) {
		cr_assert_eq(bc_arr_count(&bc), (int32_t)i, "bc_arr_count");
		cr_assert_eq(bc_arr_insert(&bc, cmp0[i]), i, "bc_arr_insert");
	}

	cr_assert_eq(memcmp(&cmp0, bc.arr, sizeof(cmp0)), 0, "memcmp");
	cr_assert_eq(bc_arr_count(&bc), 5, "bc_arr_count");

	cr_assert(bc_arr_remove(&bc, 1));  // remove [1]
	cr_assert_eq(memcmp(&cmp1, bc.arr, sizeof(cmp1)), 0, "memcmp");
	cr_assert_eq(bc_arr_count(&bc), 4, "bc_arr_count");

	cr_assert(bc_arr_remove(&bc, 0));  // remove [0]
	cr_assert_eq(memcmp(&cmp2, bc.arr, sizeof(cmp2)), 0, "memcmp");
	cr_assert_eq(bc_arr_count(&bc), 3, "bc_arr_count");

	cr_assert(bc_arr_remove(&bc, 2));  // remove [2]
	cr_assert_eq(memcmp(&cmp3, bc.arr, sizeof(cmp3)), 0, "memcmp");
	cr_assert_eq(bc_arr_count(&bc), 2, "bc_arr_count");

	cr_assert(bc_arr_remove(&bc, 0));  // remove [0]
	cr_assert_eq(memcmp(&cmp4, bc.arr, sizeof(cmp4)), 0, "memcmp");
	cr_assert_eq(bc_arr_count(&bc), 1, "bc_arr_count");

	cr_assert(bc_arr_remove(&bc, 0));  // remove [0]
	cr_assert_eq(bc_arr_count(&bc), 0, "bc_arr_count");

	bc_arr_destroy(&bc);
}


Test(bc_arr, insert_beyond_capacity_must_return_negative_one)
{
	struct bc_arr bc;
	uint16_t cmp[] = {4, 3, 2, 1, 0};

	cr_assert_eq(bc_arr_init(&bc, 5), 0, "bc_arr_init");

	cr_assert_eq(bc_arr_insert(&bc, 4), 0, "bc_arr_insert");
	cr_assert_eq(bc_arr_insert(&bc, 3), 1, "bc_arr_insert");
	cr_assert_eq(bc_arr_insert(&bc, 2), 2, "bc_arr_insert");
	cr_assert_eq(bc_arr_insert(&bc, 1), 3, "bc_arr_insert");
	cr_assert_eq(bc_arr_insert(&bc, 0), 4, "bc_arr_insert");

	cr_assert_eq(bc_arr_count(&bc), 5, "bc_arr_count");

	cr_assert_eq(bc_arr_insert(&bc, 5), -1, "bc_arr_insert");

	cr_assert_eq(memcmp(&cmp, bc.arr, sizeof(cmp)), 0, "memcmp");

	bc_arr_destroy(&bc);
}


Test(bc_arr, iterator_test)
{
	struct bc_arr bc;
	uint16_t cmp[] = {99, 88, 77, 66, 55, 44, 33, 22, 11, 0};
	uint16_t arr_size = sizeof(cmp)/sizeof(cmp[0]);

	cr_assert_eq(bc_arr_init(&bc, arr_size), 0, "bc_arr_init");

	for (uint16_t i = 0; i < arr_size; i++) {
		cr_assert_eq(bc_arr_count(&bc), (int32_t)i, "bc_arr_count");
		cr_assert_eq(bc_arr_insert(&bc, cmp[i]), i, "bc_arr_insert");
	}

	BC_ARR_FOREACH(&bc) {
		cr_assert_eq(__data, cmp[__i], "Wrong foreach");
	}

	bc_arr_destroy(&bc);
}


Test(bc_arr, maintain_insert_and_remove)
{
	struct bc_arr bc;
	uint16_t cmp0[] = {[0]=8, [1]=9}; // remove [1]
	uint16_t cmp1[] = {[0]=8}; // insert(11)
	uint16_t cmp2[] = {[0]=8, [1]=11}; // remove [0]
	uint16_t cmp3[] = {[0]=11};

	cr_assert_eq(bc_arr_init(&bc, 32), 0, "bc_arr_init");

	cr_assert_eq(bc_arr_insert(&bc, 8), 0, "bc_arr_insert");
	cr_assert_eq(bc_arr_insert(&bc, 9), 1, "bc_arr_insert");

	cr_assert_eq(memcmp(&cmp0, bc.arr, sizeof(cmp0)), 0, "memcmp");
	cr_assert_eq(bc_arr_count(&bc), 2, "bc_arr_count");


	cr_assert(bc_arr_remove(&bc, 1));  // remove [1]
	cr_assert_eq(memcmp(&cmp1, bc.arr, sizeof(cmp1)), 0, "memcmp");
	cr_assert_eq(bc_arr_count(&bc), 1, "bc_arr_count");

	cr_assert_eq(bc_arr_insert(&bc, 11), 1, "bc_arr_insert");  // insert(11)
	cr_assert_eq(memcmp(&cmp2, bc.arr, sizeof(cmp2)), 0, "memcmp");
	cr_assert_eq(bc_arr_count(&bc), 2, "bc_arr_count");

	cr_assert(bc_arr_remove(&bc, 0));  // remove [0]
	cr_assert_eq(memcmp(&cmp3, bc.arr, sizeof(cmp3)), 0, "memcmp");
	cr_assert_eq(bc_arr_count(&bc), 1, "bc_arr_count");

	cr_assert(bc_arr_remove(&bc, 0));  // remove [0]
	cr_assert_eq(bc_arr_count(&bc), 0, "bc_arr_count");

	cr_assert(!bc_arr_remove(&bc, 0));  // remove returns false
	cr_assert_eq(bc_arr_count(&bc), 0, "bc_arr_count");

	bc_arr_destroy(&bc);
}
