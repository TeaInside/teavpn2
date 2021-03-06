
#ifndef __TEAVPN2__VT_HEXDUMP_H
#define __TEAVPN2__VT_HEXDUMP_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>


#define CHDOT(C) (((32 <= (C)) && ((C) <= 126)) ? (C) : '.')
#define VT_HEXDUMP(PTR, SIZE)						\
do {									\
	size_t i, j, k = 0, l, size = (size_t)(SIZE);			\
	uint8_t *ptr = (uint8_t *)(PTR);				\
	printf("============ VT_HEXDUMP ============\n");		\
	printf("File\t\t: %s:%d\n", __FILE__, __LINE__);		\
	printf("Function\t: %s()\n", __func__);				\
	printf("Address\t\t: 0x%016lx\n", (uintptr_t)ptr);		\
	printf("Dump size\t: %zu bytes\n", (size));			\
	printf("\n");							\
	for (i = 0; i <= (size/16); i++) {				\
		printf("0x%016lx|  ", (uintptr_t)(ptr + i * 16));	\
		l = k;							\
		for (j = 0; (j < 16) && (k < size); j++, k++) {		\
			printf("%02x ", ptr[k]);			\
		}							\
		while (j++ < 16)					\
			printf("   ");					\
		printf(" |");						\
		for (j = 0; (j < 16) && (l < size); j++, l++) {		\
			printf("%c", CHDOT(ptr[l]));			\
		}							\
		printf("|\n");						\
	}								\
	printf("=====================================\n");		\
} while (0)

#include <teavpn2/base.h>

#endif /* #ifndef __TEAVPN2__VT_HEXDUMP_H */
