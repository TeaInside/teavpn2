
#ifndef TEAVPN2__VT_HEXDUMP_H
#define TEAVPN2__VT_HEXDUMP_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>


#define CHDOT(C) (((32 <= (C)) && ((C) <= 126)) ? (C) : '.')
#define VT_HEXDUMP(PTR, SIZE)						\
do {									\
	size_t i, j, k = 0, l, __size = (size_t)(SIZE);			\
	uint8_t *__ptr = (uint8_t *)(PTR);				\
	printf("================== VT_HEXDUMP ==================\n");	\
	printf("File\t\t: %s:%d\n", __FILE__, __LINE__);		\
	printf("Function\t: %s()\n", __func__);				\
	printf("Address\t\t: 0x%016zx\n", (uintptr_t)__ptr);		\
	printf("Dump size\t: %zu bytes\n", (__size));			\
	printf("\n");							\
	for (i = 0; i <= (__size/16); i++) {				\
		printf("0x%016lx|  ", (uintptr_t)(__ptr + i * 16));	\
		l = k;							\
		for (j = 0; (j < 16) && (k < __size); j++, k++) {	\
			printf("%02x ", __ptr[k]);			\
		}							\
		while (j++ < 16)					\
			printf("   ");					\
		printf(" |");						\
		for (j = 0; (j < 16) && (l < __size); j++, l++) {	\
			printf("%c", CHDOT(__ptr[l]));			\
		}							\
		printf("|\n");						\
	}								\
	printf("================================================\n");	\
	fflush(stdout);							\
} while (0)

#include <teavpn2/base.h>

#endif /* #ifndef TEAVPN2__VT_HEXDUMP_H */
