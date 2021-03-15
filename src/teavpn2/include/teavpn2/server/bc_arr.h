
#ifndef TEAVPN2__SERVER__BC_LIST_H
#define TEAVPN2__SERVER__BC_LIST_H

#include <stdlib.h>
#include <teavpn2/base.h>


/*
 * Broadcast array.
 *
 * Whenever there is a packet that should be broadcasted
 * to all clients, we use this struct to enumerate the
 * client index slot efficiently.
 */
struct bc_arr {
	uint16_t		*arr;
	uint16_t		n;
	uint16_t		max;
	struct_pad(0, 4);
};

#ifdef BC_ARR_TEST
#  define bc_arr_inline __no_inline
#else
#  define bc_arr_inline inline
#endif


static bc_arr_inline int bc_arr_init(struct bc_arr *bc, uint16_t arr_size)
{
	uint16_t *arr;

	arr = calloc(arr_size, sizeof(uint16_t));
	if (unlikely(arr == NULL))
		return -ENOMEM;

	bc->max = arr_size;
	bc->arr = arr;
	bc->n = 0;
	return 0;
}


static bc_arr_inline bool bc_arr_remove(struct bc_arr *bc, uint16_t idx)
{
	uint16_t n = bc->n;
	uint16_t max_idx = n - 1;

	if (unlikely(n == 0))
		return false;

	if (unlikely(idx > max_idx))
		return false;

	bc->n--;
	if (idx == max_idx)
		return true;

	bc->arr[idx] = bc->arr[max_idx];

	return true;
}


/*
 * Return index
 */
static bc_arr_inline int32_t bc_arr_insert(struct bc_arr *bc, uint16_t data)
{
	uint16_t n = bc->n;

	if (unlikely(n == bc->max))
		return -1;

	bc->arr[n] = data;
	bc->n++;

	return n;
}


static bc_arr_inline uint16_t bc_arr_count(struct bc_arr *bc)
{
	return bc->n;
}


static bc_arr_inline void bc_arr_destroy(struct bc_arr *bc)
{
	free(bc->arr);
	bc->arr = NULL;
}

#define BC_ARR_FOREACH(BC_ARR)			\
for (						\
	uint16_t __i = 0,			\
	__data = (BC_ARR)->arr[__i]		\
	;					\
	(__i < (BC_ARR)->n)			\
	;					\
	__data = (BC_ARR)->arr[++__i]		\
)

#endif /* #ifndef TEAVPN2__SERVER__BC_LIST_H */
