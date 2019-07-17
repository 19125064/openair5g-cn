/*
 * Copyright (c) 2015, EURECOM (www.eurecom.fr)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * The views and conclusions contained in the software and documentation are those
 * of the authors and should not be interpreted as representing official policies,
 * either expressed or implied, of the FreeBSD Project.
 */

#include <stdlib.h>
#include <stdint.h>
#include <ctype.h>

#include "conversions.h"
#include "log.h"

static const char                       hex_to_ascii_table[16] = {
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
};

static const signed char                ascii_to_hex_table[0x100] = {
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, -1, -1, -1, -1, -1, -1,
  -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1
};

void
hexa_to_ascii (
  uint8_t * from,
  char *to,
  size_t length)
{
  size_t                                 i;

  for (i = 0; i < length; i++) {
    uint8_t                                 upper = (from[i] & 0xf0) >> 4;
    uint8_t                                 lower = from[i] & 0x0f;

    to[2 * i] = hex_to_ascii_table[upper];
    to[2 * i + 1] = hex_to_ascii_table[lower];
  }
}

int
ascii_to_hex (
  uint8_t * dst,
  const char *h)
{
  const unsigned char                    *hex = (const unsigned char *)h;
  unsigned                                i = 0;

  for (;;) {
    int                                     high,
                                            low;

    while (*hex && isspace (*hex))
      hex++;

    if (!*hex)
      return 1;

    high = ascii_to_hex_table[*hex++];

    if (high < 0)
      return 0;

    while (*hex && isspace (*hex))
      hex++;

    if (!*hex)
      return 0;

    low = ascii_to_hex_table[*hex++];

    if (low < 0)
      return 0;

    dst[i++] = (high << 4) | low;
  }
}


int BIT_STRING_fromBuf(BIT_STRING_t *st, const uint8_t *str, unsigned int bit_len)
{
	void *buf;
	unsigned int len = bit_len / 8;
	if (bit_len % 8)
		len++;
  
	if (!st || (!str && len)) {
		errno = EINVAL;
		return -1;
	}
      
	if (!str) {
		free(st->buf);
		st->buf = 0;
		st->size = 0;
		st->bits_unused = 0;
		return 0;
	}
    
	buf = malloc(len);
	if (!buf) {
		errno = ENOMEM;
		return -1;
	}
    
	memcpy(buf, str, len);
	free(st->buf);
	st->buf = buf;
	st->size = len;
	st->bits_unused = (len * 8) - bit_len;
    
	return 0;
}

#define ASN1C_ASSERT(exp)    \
        if (!(exp)) { \
                fprintf(stderr, "Assert failed %s %s:%d\n", #exp, __FILE__, __LINE__); \
                abort(); \
        }

uint32_t asn1str_to_u24(const OCTET_STRING_t *in,uint32_t *tac_Value)
{
	ASN1C_ASSERT(in && in->size == sizeof(uint32_t) - 1);

	*tac_Value =  in->buf[0]  << 16 |
		          in->buf[1]  << 8  |
		          in->buf[2];
	
	return 0;
}


