// SPDX-License-Identifier: GPL-2.0
/*
 *  bluetea/bluetest/bluetest.h
 *
 *  BlueTest (Unit Test Framework for C project)
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#ifndef BLUETEA__BLUETEST__BLUETEST_H
#define BLUETEA__BLUETEST__BLUETEST_H


#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#if defined(__clang__)
#  pragma clang diagnostic push
#  pragma clang diagnostic ignored "-Wreserved-id-macro"
#endif

#ifndef __maybe_unused
#  define __maybe_unused __attribute__((unused))
#endif

#ifndef __no_return
#  define __no_return __attribute__((noreturn))
#endif

#if defined(__clang__)
#  pragma clang diagnostic pop
#endif

typedef struct _bluetest_data {
	uint32_t		n_test;
	uint32_t		n_pass;
	uint32_t		dyn_fail;
	uint32_t		dyn_pass;
} bluetest_data_t;


typedef int (*bluetest_entry_t)(uint32_t *____n_test, uint32_t *____n_pass,
				uint32_t *__dyn_fail, uint32_t *__dyn_pass);

extern bluetest_entry_t test_entry[];

extern bool will_run_test(void);
extern bool print_test(bool is_success, const char *func, const char *file,
			int line);
extern bool print_test_s(bool is_success, const char *func, const char *file,
				int line);
extern void filename_resolve(char *buf, size_t bufsiz, const char *filename,
			      size_t len);



#define FN_BLUETEST(PACKAGE, NAME) test_##PACKAGE##_##NAME

#define BLUETEST(PACKAGE, NAME)						\
int FN_BLUETEST(PACKAGE, NAME)(uint32_t __maybe_unused *____n_test,	\
			      uint32_t __maybe_unused *____n_pass,	\
			      uint32_t __maybe_unused *__dyn_fail,	\
			      uint32_t __maybe_unused *__dyn_pass)


#define TQ_START 							\
	int ____ret = (0); 						\
	char __file[2048]; 						\
	filename_resolve(__file, sizeof(__file), __FILE__,		\
			 sizeof(__FILE__))

#define TQ_RETURN return ____ret
#define TQ_IF_RUN if (will_run_test())

#define TQ_ASSERT(EXPR)							\
do {									\
	bool __is_success;						\
									\
	if (will_run_test()) {						\
		__is_success = (EXPR);					\
		if (print_test(__is_success, __func__ + 5, __file,	\
	                       __LINE__))				\
			(*____n_pass)++;				\
		else							\
			____ret = 1;					\
	} else {							\
		(*____n_test)++;					\
	}								\
} while (0)


#define TQ_ASSERT_DYN(EXPR)						\
do {									\
	bool __is_success;						\
									\
	if (will_run_test()) {						\
		__is_success = (EXPR);					\
		if (!print_test(__is_success, __func__ + 5, __file,	\
	                       __LINE__)) {				\
			____ret = 1;					\
			(*__dyn_fail)++;				\
			printf("\x1b[31mDYNAMIC TEST FAILED!\x1b[0m\n");\
		} else {						\
			(*__dyn_pass)++;				\
		}							\
	}								\
} while (0)


#define TQ_ASSERT_DYN_S(EXPR)						\
do {									\
	bool __is_success;						\
									\
	if (will_run_test()) {						\
		__is_success = (EXPR);					\
		if (!print_test_s(__is_success, __func__ + 5, __file,	\
	                          __LINE__)) {				\
			____ret = 1;					\
			(*__dyn_fail)++;				\
			printf("\x1b[31mDYNAMIC TEST FAILED!\x1b[0m\n");\
		} else {						\
			(*__dyn_pass)++;				\
		}							\
	}								\
} while (0)


#define TQ_ASSERT_S(EXPR)						\
do {									\
	bool __is_success;						\
									\
	if (will_run_test()) {						\
		__is_success = (EXPR);					\
		if (print_test_s(__is_success, __func__ + 5, __file,	\
	                       __LINE__))				\
			(*____n_pass)++;				\
		else							\
			____ret = 1;					\
	} else {							\
		(*____n_test)++;					\
	}								\
} while (0)

#define MEM_BARRIER(PTR) __asm__ volatile("":"+r"(PTR)::"memory")

#define TQ_VOID(EXPR)			\
do {					\
	if (will_run_test()) {		\
		(EXPR);			\
	}				\
} while (0)


#endif /* #ifndef BLUETEA__BLUETEST__BLUETEST_H */
