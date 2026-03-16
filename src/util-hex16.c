// Modified version of https://github.com/NLnetLabs/simdzone/blob/main/src/generic/base16.h

/*
 * base16.h -- Fast Base16 stream decoder
 *
 * Copyright (c) 2005-2016, Nick Galbreath.
 * Copyright (c) 2022, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 */
#include "util-hex16.h"

// adaptation of base16 decoder by Nick Galbreath to operate similar to the
// base64 stream decoder by Alfred Klomp.
// https://github.com/client9/stringencoders
// https://github.com/aklomp/base64

struct base16_state {
  int eof;
  int bytes;
  unsigned char carry;
};

#define BASE16_EOF 1

static const uint32_t base16_table_dec_32bit_d0[256] = {
  256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
  256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
  256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
  256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 257, 256,
  0, 16, 32, 48, 64, 80, 96, 112, 128, 144, 256, 256,
  256, 256, 256, 256, 256, 160, 176, 192, 208, 224, 240, 256,
  256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
  256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
  256, 160, 176, 192, 208, 224, 240, 256, 256, 256, 256, 256,
  256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
  256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
  256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
  256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
  256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
  256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
  256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
  256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
  256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
  256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
  256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
  256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
  256, 256, 256, 256
};

static const uint32_t base16_table_dec_32bit_d1[256] = {
  256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
  256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
  256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
  256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 257, 256,
  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 256, 256,
  256, 256, 256, 256, 256, 10, 11, 12, 13, 14, 15, 256,
  256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
  256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
  256, 10, 11, 12, 13, 14, 15, 256, 256, 256, 256, 256,
  256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
  256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
  256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
  256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
  256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
  256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
  256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
  256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
  256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
  256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
  256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
  256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
  256, 256, 256, 256
};

static inline int
base16_dec_loop_generic_32_inner(
  const uint8_t **s, uint8_t **o, size_t *rounds)
{
  const uint32_t val1 = base16_table_dec_32bit_d0[(*s)[0]]
                      | base16_table_dec_32bit_d1[(*s)[1]];
  const uint32_t val2 = base16_table_dec_32bit_d0[(*s)[2]]
                      | base16_table_dec_32bit_d1[(*s)[3]];

  if (val1 > 0xff || val2 > 0xff)
    return 0;

  (*o)[0] = (uint8_t)val1;
  (*o)[1] = (uint8_t)val2;

  *s += 4;
  *o += 2;
  *rounds -= 1;

  return 1;
}

static inline void
base16_dec_loop_generic_32(
  const uint8_t **s, size_t *slen, uint8_t **o, size_t *olen)
{
  if (*slen < 4)
    return;

  // some comment on the how and what...
  size_t rounds = (*slen - 4) / 4;

  *slen -= rounds * 4; // 4 bytes consumed per round
  *olen += rounds * 2; // 2 bytes produced per round

  do {
    if (rounds >= 8) {
      if (base16_dec_loop_generic_32_inner(s, o, &rounds) &&
          base16_dec_loop_generic_32_inner(s, o, &rounds) &&
          base16_dec_loop_generic_32_inner(s, o, &rounds) &&
          base16_dec_loop_generic_32_inner(s, o, &rounds) &&
          base16_dec_loop_generic_32_inner(s, o, &rounds) &&
          base16_dec_loop_generic_32_inner(s, o, &rounds) &&
          base16_dec_loop_generic_32_inner(s, o, &rounds) &&
          base16_dec_loop_generic_32_inner(s, o, &rounds))
        continue;
      break;
    }
    if (rounds >= 4) {
      if (base16_dec_loop_generic_32_inner(s, o, &rounds) &&
          base16_dec_loop_generic_32_inner(s, o, &rounds) &&
          base16_dec_loop_generic_32_inner(s, o, &rounds) &&
          base16_dec_loop_generic_32_inner(s, o, &rounds))
        continue;
      break;
    }
    if (rounds >= 2) {
      if (base16_dec_loop_generic_32_inner(s, o, &rounds) &&
          base16_dec_loop_generic_32_inner(s, o, &rounds))
        continue;
      break;
    }
    base16_dec_loop_generic_32_inner(s, o, &rounds);
    break;
  } while (rounds > 0);

  // Adjust for any rounds that were skipped:
  *slen += rounds * 4;
  *olen -= rounds * 2;
}


static inline int base16_stream_decode(
  struct base16_state *state,
  const char *src,
  size_t srclen,
  uint8_t *out,
  size_t *outlen)
{
    int ret = 0;
    const uint8_t *s = (const uint8_t *) src;
    uint8_t *o = (uint8_t *) out;
    uint32_t q;
    
    // Use local temporaries to avoid cache thrashing:
    size_t olen = 0;
    size_t slen = srclen;
    struct base16_state st;
    st.eof = state->eof;
    st.bytes = state->bytes;
    st.carry = state->carry;
    
    if (st.eof) {
        *outlen = 0;
        return ret;
    }
    
    // Duff's device again:
    switch (st.bytes)
    {
        
        for (;;)
        {
        case 0:
            base16_dec_loop_generic_32(&s, &slen, &o, &olen);
            if (slen-- == 0) {
                ret = 1;
                break;
            }
            if ((q = base16_table_dec_32bit_d0[*s++]) >= 255) {
                st.eof = BASE16_EOF;
                break;
            }
            st.carry = (uint8_t)q;
            st.bytes = 1;
            
            // fallthrough
            
        case 1:
            if (slen-- == 0) {
                ret = 1;
                break;
            }
            if ((q = base16_table_dec_32bit_d1[*s++]) >= 255) {
                st.eof = BASE16_EOF;
                break;
            }
            *o++ = st.carry | (uint8_t)q;
            st.carry = 0;
            st.bytes = 0;
            olen++;
        }
    }
    
    state->eof = st.eof;
    state->bytes = st.bytes;
    state->carry = st.carry;
    *outlen = olen;
    return ret;
}


int base16_decode(
  const char *src, size_t srclen, uint8_t *out, size_t *outlen)
{
  struct base16_state state = { .eof = 0, .bytes = 0, .carry = 0 };
  return base16_stream_decode(&state, src, srclen, out, outlen) & !state.bytes;
}
