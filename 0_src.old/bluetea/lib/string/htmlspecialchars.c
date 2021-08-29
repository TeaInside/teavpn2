// SPDX-License-Identifier: GPL-2.0
/*
 *  bluetea/lib/string/htmlspecialchars.c
 *
 *  String library
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#include <bluetea/lib/string.h>


struct html_char_map {
	const char	to[8];
	const uint8_t	len;
};


static const struct html_char_map html_map[0x100u] = {
	['<']  = {"&lt;",	4},
	['>']  = {"&gt;",	4},
	['"']  = {"&quot;",	6},
	['\''] = {"&#039;",	6},
	['&']  = {"&amp;",	5},
};


__no_inline size_t htmlspecialchars(char *__restrict__ _out, size_t outlen,
				    const char *__restrict__ _in)
{
	unsigned char c;
	unsigned char *__restrict__ out = (unsigned char *)_out;
	const unsigned char *__restrict__ in  = (const unsigned char *)_in;
	const unsigned char *out_end = (const unsigned char *)(_out + outlen);

	if (unlikely(outlen == 0 || *in == '\0'))
		return 0;

	/*
	 * IMPORTANT:
	 * Don't alter `out_end[0]`, it is beyond the allowed area for writing.
	 */
	while ((c = *in)) {
		const struct html_char_map *map_to = &html_map[(size_t)c];

		if (likely(*map_to->to == '\0')) {
			/*
			 * We don't have this character on the map.
			 * Don't translate this character!
			 */
			if (unlikely(out + 1 >= out_end)) {
				/*
				 * We run out of buffer, don't copy!
				 */
				break;
			}

			*out++ = c;
		} else {
			/*
			 * We find the corresponding character on the map.
			 * Translate this character!
			 */
			size_t len = map_to->len;
			if (unlikely(out + len >= out_end)) {
				/*
				 * We run out of buffer, don't copy!
				 */
				break;
			}

			short_memcpy(out, map_to->to, (uint8_t)len);
			out += len;
		}
		in++;
	}

	*out = '\0';
	return (size_t)(out - (unsigned char *)_out);
}



__no_inline size_t htmlspecialcharsl(char *__restrict__ _out, size_t outlen,
				     const char *__restrict__ _in, size_t inlen)
{
	unsigned char *__restrict__ out = (unsigned char *)_out;
	const unsigned char *__restrict__ in  = (const unsigned char *)_in;
	const unsigned char *in_end  = (const unsigned char *)(_in + inlen);
	const unsigned char *out_end = (const unsigned char *)(_out + outlen);

	if (unlikely(outlen == 0 || inlen == 0))
		return 0;

	/*
	 * IMPORTANT:
	 * Don't alter `out_end[0]`, it is beyond the allowed area for writing.
	 */
	while (in < in_end) {
		unsigned char c = *in;
		const struct html_char_map *map_to = &html_map[(size_t)c];

		if (likely(*map_to->to == '\0')) {
			/*
			 * We don't have this character on the map.
			 * Don't translate this character!
			 */
			if (unlikely(out + 1 >= out_end)) {
				/*
				 * We run out of buffer, don't copy!
				 */
				break;
			}

			*out++ = c;
		} else {
			/*
			 * We find the corresponding character on the map.
			 * Translate this character!
			 */
			size_t len = map_to->len;
			if (unlikely(out + len >= out_end)) {
				/*
				 * We run out of buffer, don't copy!
				 */
				break;
			}

			short_memcpy(out, map_to->to, (uint8_t)len);
			out += len;
		}
		in++;
	}

	*out = '\0';
	return (size_t)(out - (unsigned char *)_out);
}
