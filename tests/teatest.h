// SPDX-License-Identifier: GPL-2.0-only
/*
 *  tests/teatest.c
 *
 *  Tea Test (Unit Test Framework for C project)
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#ifndef TESTS__TEATEST_H
#define TESTS__TEATEST_H

#include <libgen.h>
#include <teavpn2/base.h>


typedef int (*test_entry_t)(uint32_t *____total_credit, uint32_t *____credit);

int init_test(const test_entry_t *tests);
int run_test(const test_entry_t *tests);

bool tq_assert_hook(void);
bool print_test(bool is_success, const char *func, const char *file, int line);
int spawn_valgrind(int argc, char *argv[]);


/* TODO: Make core dump */
#define core_dump()

#define TEATEST_FN(PACKAGE, NAME) test_##PACKAGE##_##NAME

#define TEATEST(PACKAGE, NAME)					\
int TEATEST_FN(PACKAGE, NAME)(uint32_t *____total_credit,	\
			      uint32_t *____credit)		\




#define TQ_ASSERT(EXPR)							\
do {									\
	bool __is_success;						\
	char __fn0[1024] = __FILE__;					\
	char __fn1[1024] = __FILE__;					\
	char __file[2048];						\
									\
	snprintf(__file, sizeof(__file), "%s/%s",			\
		 basename(dirname(__fn0)), basename(__fn1));		\
									\
	if (tq_assert_hook()) {						\
		__is_success = (EXPR);					\
		if (print_test(__is_success, __func__, __file,		\
	                       __LINE__))				\
			(*____credit)++;				\
	} else {							\
		(*____total_credit)++;					\
	}								\
} while (0)


#define cr_assert_eq(A, B, C) TQ_ASSERT((A) == (B))
#define cr_assert TQ_ASSERT


#endif /* #ifndef TESTS__TEATEST_H */
