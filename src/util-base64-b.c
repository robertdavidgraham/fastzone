#include "util-base64-b.h"

#include <stdint.h>

#if defined(__SSE2__)
  #include <emmintrin.h>
#endif

#if defined(__aarch64__) || defined(_M_ARM64)
  #include <arm_neon.h>
#endif

/* Decode map:
   - 0..63  : valid sextet
   - 0x80   : invalid
   - 0x81   : '=' padding
*/
static const uint8_t b64dec_map[256] = {
#define XX 0x80
#define EQ 0x81
    XX,XX,XX,XX,XX,XX,XX,XX, XX,XX,XX,XX,XX,XX,XX,XX,
    XX,XX,XX,XX,XX,XX,XX,XX, XX,XX,XX,XX,XX,XX,XX,XX,
    XX,XX,XX,XX,XX,XX,XX,XX, XX,XX,XX,62,XX,XX,XX,63, /* '+' '/' */
    52,53,54,55,56,57,58,59, 60,61,XX,XX,XX,EQ,XX,XX, /* '0'-'9' '=' */
    XX, 0, 1, 2, 3, 4, 5, 6,  7, 8, 9,10,11,12,13,14,
    15,16,17,18,19,20,21,22, 23,24,25,XX,XX,XX,XX,XX,
    XX,26,27,28,29,30,31,32, 33,34,35,36,37,38,39,40,
    41,42,43,44,45,46,47,48, 49,50,51,XX,XX,XX,XX,XX,
    XX,XX,XX,XX,XX,XX,XX,XX, XX,XX,XX,XX,XX,XX,XX,XX,
    XX,XX,XX,XX,XX,XX,XX,XX, XX,XX,XX,XX,XX,XX,XX,XX,
    XX,XX,XX,XX,XX,XX,XX,XX, XX,XX,XX,XX,XX,XX,XX,XX,
    XX,XX,XX,XX,XX,XX,XX,XX, XX,XX,XX,XX,XX,XX,XX,XX,
    XX,XX,XX,XX,XX,XX,XX,XX, XX,XX,XX,XX,XX,XX,XX,XX,
    XX,XX,XX,XX,XX,XX,XX,XX, XX,XX,XX,XX,XX,XX,XX,XX,
    XX,XX,XX,XX,XX,XX,XX,XX, XX,XX,XX,XX,XX,XX,XX,XX,
    XX,XX,XX,XX,XX,XX,XX,XX, XX,XX,XX,XX,XX,XX,XX,XX
#undef XX
#undef EQ
};

static inline int is_sp_or_tab(uint8_t c) {
    return (c == 0x20u) | (c == 0x09u);
}

static inline void b64_write3(unsigned char *out, uint32_t v24)
{
    out[0] = (unsigned char)(v24 >> 16);
    out[1] = (unsigned char)(v24 >>  8);
    out[2] = (unsigned char)(v24 >>  0);
}

/* Decode 4 chars known-valid (no '=' and no whitespace). */
static inline void b64_decode4_noeq(const unsigned char *in4, unsigned char *out3)
{
    uint32_t a = (uint32_t)b64dec_map[in4[0]];
    uint32_t b = (uint32_t)b64dec_map[in4[1]];
    uint32_t c = (uint32_t)b64dec_map[in4[2]];
    uint32_t d = (uint32_t)b64dec_map[in4[3]];
    uint32_t v = (a << 18) | (b << 12) | (c << 6) | d;
    b64_write3(out3, v);
}

/* Return nonzero if 16 bytes are all valid base64 alphabet and contain no '=' and no space/tab. */
static inline int b64_simd_all_valid_noeq_nowhite_16(const unsigned char *p)
{
#if defined(__SSE2__)
    __m128i x     = _mm_loadu_si128((const __m128i*)(const void*)p);

    __m128i eq    = _mm_set1_epi8('=');
    __m128i sp    = _mm_set1_epi8(' ');
    __m128i tab   = _mm_set1_epi8('\t');
    __m128i plus  = _mm_set1_epi8('+');
    __m128i slash = _mm_set1_epi8('/');

    __m128i A0  = _mm_set1_epi8('A' - 1);
    __m128i AZ  = _mm_set1_epi8('Z' + 1);
    __m128i a0  = _mm_set1_epi8('a' - 1);
    __m128i az  = _mm_set1_epi8('z' + 1);
    __m128i n0  = _mm_set1_epi8('0' - 1);
    __m128i n9  = _mm_set1_epi8('9' + 1);

    __m128i geA = _mm_cmpgt_epi8(x, A0);
    __m128i ltZ = _mm_cmplt_epi8(x, AZ);
    __m128i isAZ= _mm_and_si128(geA, ltZ);

    __m128i gea = _mm_cmpgt_epi8(x, a0);
    __m128i ltz = _mm_cmplt_epi8(x, az);
    __m128i isaz= _mm_and_si128(gea, ltz);

    __m128i gen = _mm_cmpgt_epi8(x, n0);
    __m128i ltn = _mm_cmplt_epi8(x, n9);
    __m128i is09= _mm_and_si128(gen, ltn);

    __m128i isPlus  = _mm_cmpeq_epi8(x, plus);
    __m128i isSlash = _mm_cmpeq_epi8(x, slash);

    __m128i valid = _mm_or_si128(_mm_or_si128(isAZ, isaz),
                                 _mm_or_si128(is09, _mm_or_si128(isPlus, isSlash)));

    __m128i bad = _mm_or_si128(_mm_cmpeq_epi8(x, eq),
                 _mm_or_si128(_mm_cmpeq_epi8(x, sp), _mm_cmpeq_epi8(x, tab)));

    return (_mm_movemask_epi8(valid) == 0xFFFF) && (_mm_movemask_epi8(bad) == 0);

#elif defined(__aarch64__) || defined(_M_ARM64)
    uint8x16_t x = vld1q_u8(p);

    uint8x16_t isAZ = vandq_u8(vcgeq_u8(x, vdupq_n_u8((uint8_t)'A')),
                              vcleq_u8(x, vdupq_n_u8((uint8_t)'Z')));
    uint8x16_t isaz = vandq_u8(vcgeq_u8(x, vdupq_n_u8((uint8_t)'a')),
                              vcleq_u8(x, vdupq_n_u8((uint8_t)'z')));
    uint8x16_t is09 = vandq_u8(vcgeq_u8(x, vdupq_n_u8((uint8_t)'0')),
                              vcleq_u8(x, vdupq_n_u8((uint8_t)'9')));
    uint8x16_t isPlus  = vceqq_u8(x, vdupq_n_u8((uint8_t)'+'));
    uint8x16_t isSlash = vceqq_u8(x, vdupq_n_u8((uint8_t)'/'));
    uint8x16_t isEq    = vceqq_u8(x, vdupq_n_u8((uint8_t)'='));
    uint8x16_t isSp    = vceqq_u8(x, vdupq_n_u8((uint8_t)' '));
    uint8x16_t isTab   = vceqq_u8(x, vdupq_n_u8((uint8_t)'\t'));

    uint8x16_t valid = vorrq_u8(vorrq_u8(isAZ, isaz),
                                vorrq_u8(is09, vorrq_u8(isPlus, isSlash)));

    uint8x16_t invalid = vmvnq_u8(valid);
    uint8_t inv_any = vmaxvq_u8(invalid);
    uint8_t bad_any = vmaxvq_u8(vorrq_u8(isEq, vorrq_u8(isSp, isTab)));
    return (inv_any == 0) && (bad_any == 0);
#else
    (void)p;
    return 0;
#endif
}

/* Gather next meaningful char (skipping only space/tab). Returns 1 if found, 0 if end. */
static inline int next_nonwhite(const unsigned char *p, size_t in_length, size_t *i, uint8_t *c)
{
    size_t k = *i;
    while (k < in_length) {
        uint8_t x = p[k];
        if (!is_sp_or_tab(x)) { *c = x; *i = k; return 1; }
        k++;
    }
    *i = k;
    return 0;
}

size_t base64decode(const char *in,
                    size_t in_length,
                    unsigned char *out,
                    size_t *out_len,
                    int *err)
{
    size_t i = 0;
    size_t o = 0;

    if (!in || !out || !out_len || !err) {
        if (err) *err = BASE64DEC_ERR_NULL;
        if (out_len) *out_len = 0;
        return 0;
    }
    *err = BASE64DEC_ERR_NONE;

    const unsigned char *p = (const unsigned char *)(const void *)in;

    /* Bulk decode only across contiguous runs of pure base64 chars (no '=' and no space/tab). */
    for (;;) {
        while (i < in_length && is_sp_or_tab(p[i])) i++;

        /* Semantic bound: don’t *consume* beyond in_length, but loads may read past end safely. */
        if (i + 16 > in_length) break;
        if (!b64_simd_all_valid_noeq_nowhite_16(p + i)) break;

        b64_decode4_noeq(p + i +  0, out + o +  0);
        b64_decode4_noeq(p + i +  4, out + o +  3);
        b64_decode4_noeq(p + i +  8, out + o +  6);
        b64_decode4_noeq(p + i + 12, out + o +  9);

        i += 16;
        o += 12;
    }

    /* General path: skip space/tab; stop at first non-valid. */
    for (;;) {
        uint8_t c[4], v[4];
        int have = 0;

        while (have < 4) {
            uint8_t ch;
            if (!next_nonwhite(p, in_length, &i, &ch)) {
                /* end */
                if (have == 0) { *out_len = o; return i; }
                *err |= BASE64DEC_ERR_INVALID_LENGTH;
                *out_len = o;
                return i;
            }

            uint8_t mv = b64dec_map[ch];
            if (mv == 0x80) {
                if (ch != '\r' && ch != '\n')
                    *err |= BASE64DEC_ERR_INVALID_CHAR;
                *out_len = o;
                return i; /* stop before invalid char, not consumed */
            }

            c[have] = ch;
            v[have] = mv;
            i++;      /* consume this meaningful char */
            have++;
        }

        /* First two may not be '=' */
        if (v[0] == 0x81 || v[1] == 0x81) {
            *err |= BASE64DEC_ERR_INVALID_PADDING;
            *out_len = o;
            return i;
        }

        if (v[2] == 0x81) {
            /* xx== */
            if (v[3] != 0x81) {
                *err |= BASE64DEC_ERR_INVALID_PADDING;
                *out_len = o;
                return i;
            }
            {
                uint32_t a = (uint32_t)v[0];
                uint32_t b = (uint32_t)v[1];
                uint32_t vv = (a << 18) | (b << 12);
                out[o++] = (unsigned char)(vv >> 16);
            }
            /* After padding: allow only space/tab then stop (or end). */
            while (i < in_length && is_sp_or_tab(p[i])) i++;
            *out_len = o;
            return i;
        }

        if (v[3] == 0x81) {
            /* xxx= */
            {
                uint32_t a = (uint32_t)v[0];
                uint32_t b = (uint32_t)v[1];
                uint32_t c2 = (uint32_t)v[2];
                uint32_t vv = (a << 18) | (b << 12) | (c2 << 6);
                out[o++] = (unsigned char)(vv >> 16);
                out[o++] = (unsigned char)(vv >>  8);
            }
            while (i < in_length && is_sp_or_tab(p[i])) i++;
            *out_len = o;
            return i;
        }

        /* no padding */
        {
            uint32_t a = (uint32_t)v[0];
            uint32_t b = (uint32_t)v[1];
            uint32_t c2 = (uint32_t)v[2];
            uint32_t d = (uint32_t)v[3];
            uint32_t vv = (a << 18) | (b << 12) | (c2 << 6) | d;
            b64_write3(out + o, vv);
            o += 3;
        }
    }
}

