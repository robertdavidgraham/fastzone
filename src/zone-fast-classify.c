#include "zone-fast-classify.h"

#include <string.h>
#include <stdio.h>

#if defined(_MSC_VER)
#  include <intrin.h>
#endif

#ifdef SIMD_SSE2
#  include <emmintrin.h>
#endif

#ifdef SIMD_SSE42
#  include <nmmintrin.h>
#endif

#ifdef SIMD_AVX2
#  include <immintrin.h>
#endif

#ifdef SIMD_AVX512
#  include <immintrin.h>
#endif

#ifdef SIMD_NEON32
#  include <arm_neon.h>
#endif

#ifdef SIMD_NEON64
#  include <arm_neon.h>
#endif

#ifdef SIMD_SVE2
#  include <arm_sve.h>
#endif

#ifdef SIMD_RISCVV
#  include <riscv_vector.h>
#endif

#define REPEAT8(x) (UINT64_C(0x0101010101010101) * (uint64_t)(uint8_t)(x))

zone_fast_classify_fn zone_fast_classify = 0;

static void classify_scalar1(const char *data, size_t max, tokentape_t *tape_whitespace, tokentape_t *tape_intoken);
static void classify_scalar2(const char *data, size_t max, tokentape_t *tape_whitespace, tokentape_t *tape_intoken);
static void classify_swar(const char *data, size_t max, tokentape_t *tape_whitespace, tokentape_t *tape_intoken);

#ifdef SIMD_SSE2
static void classify_sse2(const char *data, size_t max, tokentape_t *tape_whitespace, tokentape_t *tape_intoken);
#endif
#ifdef SIMD_SSE42
static void classify_sse42(const char *data, size_t max, tokentape_t *tape_whitespace, tokentape_t *tape_intoken);
#endif
#ifdef SIMD_AVX2
static void classify_avx2(const char *data, size_t max, tokentape_t *tape_whitespace, tokentape_t *tape_intoken);
#endif
#ifdef SIMD_AVX512
static void classify_avx512(const char *data, size_t max, tokentape_t *tape_whitespace, tokentape_t *tape_intoken);
#endif
#ifdef SIMD_NEON32
static void classify_neon32(const char *data, size_t max, tokentape_t *tape_whitespace, tokentape_t *tape_intoken);
#endif
#ifdef SIMD_NEON64
static void classify_neon64(const char *data, size_t max, tokentape_t *tape_whitespace, tokentape_t *tape_intoken);
#endif
#ifdef SIMD_SVE2
static void classify_sve2(const char *data, size_t max, tokentape_t *tape_whitespace, tokentape_t *tape_intoken);
#endif
#ifdef SIMD_RISCVV
static void classify_riscvv(const char *data, size_t max, tokentape_t *tape_whitespace, tokentape_t *tape_intoken);
#endif

static unsigned char classify_table[256];
static int classify_table_ready = 0;

static always_inline size_t
classify_word_count(size_t max)
{
    size_t nbytes = max + 64u;
    return (nbytes + 63u) >> 6;
}

static always_inline uint64_t
load64_aligned(const void *p)
{
    return *(const uint64_t *)p;
}

static void
zone_fast_classify_make_table(void)
{
    unsigned i;
    for (i = 0; i < 256; i++) {
        unsigned char c = (unsigned char)i;
        unsigned char v = 0;

        if (c == ' ' || c == '\t')
            v |= 0x01u;

        if (c == '\r' || c == '\n')
            v |= 0x02u;

        classify_table[i] = v;
    }

    classify_table_ready = 1;
}

static always_inline uint64_t
swar_eq_hi_mask(uint64_t x, unsigned char c)
{
    uint64_t y = x ^ REPEAT8(c);
    return (y - REPEAT8(0x01)) & ~y & REPEAT8(0x80);
}

static always_inline unsigned
swar_pack8_from_hi(uint64_t hi_mask)
{
    uint64_t b = hi_mask >> 7;
    return (unsigned)(((b * UINT64_C(0x0102040810204080)) >> 56) & 0xFFu);
}

/* ------------------------------------------------------- */
/* scalar1                                                 */
/* ------------------------------------------------------- */

static void
classify_scalar1(const char *data, size_t max,
                 tokentape_t *tape_whitespace,
                 tokentape_t *tape_intoken)
{
    size_t w, nwords;

    if (!classify_table_ready)
        zone_fast_classify_make_table();

    nwords = classify_word_count(max);

    for (w = 0; w < nwords; w++) {
        const unsigned char *p = (const unsigned char *)data + (w << 6);
        uint64_t ws_stop = 0;
        uint64_t eol_stop = 0;
        unsigned i;

        for (i = 0; i < 64; i++) {
            unsigned char v = classify_table[p[i]];
            ws_stop  |= (uint64_t)((v & 0x01u) != 0) << i;
            eol_stop |= (uint64_t)((v & 0x02u) != 0) << i;
        }

        tape_whitespace[w] = maybe_reverse(~ws_stop);
        tape_intoken[w] = maybe_reverse(ws_stop | eol_stop);
    }

    tape_whitespace[nwords] = 0;
    tape_intoken[nwords] = ~UINT64_C(0);
}

/* ------------------------------------------------------- */
/* scalar2                                                 */
/* ------------------------------------------------------- */

static void
classify_scalar2(const char *data, size_t max,
                 tokentape_t *tape_whitespace,
                 tokentape_t *tape_intoken)
{
    size_t w, nwords;

    nwords = classify_word_count(max);

    for (w = 0; w < nwords; w++) {
        const unsigned char *p = (const unsigned char *)data + (w << 6);
        uint64_t ws_stop = 0;
        uint64_t eol_stop = 0;
        unsigned i;

        for (i = 0; i < 64; i++) {
            unsigned char c = p[i];
            unsigned is_ws  = (unsigned)(c == ' ' || c == '\t');
            unsigned is_eol = (unsigned)(c == '\r' || c == '\n');

            ws_stop  |= (uint64_t)is_ws << i;
            eol_stop |= (uint64_t)is_eol << i;
        }

        tape_whitespace[w] = maybe_reverse(~ws_stop);
        tape_intoken[w] = maybe_reverse(ws_stop | eol_stop);
    }

    tape_whitespace[nwords] = 0;
    tape_intoken[nwords] = ~UINT64_C(0);
}

/* ------------------------------------------------------- */
/* swar                                                    */
/* ------------------------------------------------------- */

static always_inline unsigned
classify_swar8_ws_stop(uint64_t x)
{
    uint64_t stop = swar_eq_hi_mask(x, ' ')
                  | swar_eq_hi_mask(x, '\t');
    return swar_pack8_from_hi(stop);
}

static always_inline unsigned
classify_swar8_eol_stop(uint64_t x)
{
    uint64_t stop = swar_eq_hi_mask(x, '\r')
                  | swar_eq_hi_mask(x, '\n');
    return swar_pack8_from_hi(stop);
}

static void
classify_swar(const char *data, size_t max,
              tokentape_t *tape_whitespace,
              tokentape_t *tape_intoken)
{
    size_t w, nwords;

    nwords = classify_word_count(max);

    for (w = 0; w < nwords; w++) {
        const unsigned char *p = (const unsigned char *)data + (w << 6);
        uint64_t ws_stop = 0;
        uint64_t eol_stop = 0;
        unsigned k;

        for (k = 0; k < 8; k++) {
            uint64_t x = load64_aligned(p + (k << 3));
            ws_stop  |= (uint64_t)classify_swar8_ws_stop(x)  << (k << 3);
            eol_stop |= (uint64_t)classify_swar8_eol_stop(x) << (k << 3);
        }

        tape_whitespace[w] = maybe_reverse(~ws_stop);
        tape_intoken[w] = maybe_reverse(ws_stop | eol_stop);
    }

    tape_whitespace[nwords] = 0;
    tape_intoken[nwords] = ~UINT64_C(0);
}

#ifdef SIMD_SSE2
/* ------------------------------------------------------- */
/* sse2                                                    */
/* ------------------------------------------------------- */

static always_inline unsigned
movemask16_ws_stop_sse2(__m128i v)
{
    __m128i sp = _mm_cmpeq_epi8(v, _mm_set1_epi8(' '));
    __m128i tb = _mm_cmpeq_epi8(v, _mm_set1_epi8('\t'));
    return (unsigned)_mm_movemask_epi8(_mm_or_si128(sp, tb));
}

static always_inline unsigned
movemask16_eol_stop_sse2(__m128i v)
{
    __m128i cr = _mm_cmpeq_epi8(v, _mm_set1_epi8('\r'));
    __m128i lf = _mm_cmpeq_epi8(v, _mm_set1_epi8('\n'));
    return (unsigned)_mm_movemask_epi8(_mm_or_si128(cr, lf));
}

static void
classify_sse2(const char *data, size_t max,
              tokentape_t *tape_whitespace,
              tokentape_t *tape_intoken)
{
    size_t w, nwords;

    nwords = classify_word_count(max);

    for (w = 0; w < nwords; w++) {
        const char *p = data + (w << 6);
        __m128i v0 = _mm_load_si128((const __m128i *)(const void *)(p +  0));
        __m128i v1 = _mm_load_si128((const __m128i *)(const void *)(p + 16));
        __m128i v2 = _mm_load_si128((const __m128i *)(const void *)(p + 32));
        __m128i v3 = _mm_load_si128((const __m128i *)(const void *)(p + 48));

        uint64_t ws_stop  =  (uint64_t)movemask16_ws_stop_sse2(v0)
                           | ((uint64_t)movemask16_ws_stop_sse2(v1)  << 16)
                           | ((uint64_t)movemask16_ws_stop_sse2(v2)  << 32)
                           | ((uint64_t)movemask16_ws_stop_sse2(v3)  << 48);

        uint64_t eol_stop =  (uint64_t)movemask16_eol_stop_sse2(v0)
                           | ((uint64_t)movemask16_eol_stop_sse2(v1) << 16)
                           | ((uint64_t)movemask16_eol_stop_sse2(v2) << 32)
                           | ((uint64_t)movemask16_eol_stop_sse2(v3) << 48);

        tape_whitespace[w] = ~ws_stop;
        tape_intoken[w] = ws_stop | eol_stop;
    }

    tape_whitespace[nwords] = 0;
    tape_intoken[nwords] = ~UINT64_C(0);
}
#endif

#ifdef SIMD_SSE42
/* ------------------------------------------------------- */
/* sse4.2                                                  */
/* ------------------------------------------------------- */

static void
classify_sse42(const char *data, size_t max,
               tokentape_t *tape_whitespace,
               tokentape_t *tape_intoken)
{
    classify_sse2(data, max, tape_whitespace, tape_intoken);
}
#endif

#ifdef SIMD_AVX2
/* ------------------------------------------------------- */
/* avx2                                                    */
/* ------------------------------------------------------- */

static always_inline unsigned
movemask32_ws_stop_avx2(__m256i v)
{
    __m256i sp = _mm256_cmpeq_epi8(v, _mm256_set1_epi8(' '));
    __m256i tb = _mm256_cmpeq_epi8(v, _mm256_set1_epi8('\t'));
    return (unsigned)_mm256_movemask_epi8(_mm256_or_si256(sp, tb));
}

static always_inline unsigned
movemask32_eol_stop_avx2(__m256i v)
{
    __m256i cr = _mm256_cmpeq_epi8(v, _mm256_set1_epi8('\r'));
    __m256i lf = _mm256_cmpeq_epi8(v, _mm256_set1_epi8('\n'));
    return (unsigned)_mm256_movemask_epi8(_mm256_or_si256(cr, lf));
}

static void
classify_avx2(const char *data, size_t max,
              tokentape_t *tape_whitespace,
              tokentape_t *tape_intoken)
{
    size_t w, nwords;

    nwords = classify_word_count(max);

    for (w = 0; w < nwords; w++) {
        const char *p = data + (w << 6);
        __m256i v0 = _mm256_load_si256((const __m256i *)(const void *)(p +  0));
        __m256i v1 = _mm256_load_si256((const __m256i *)(const void *)(p + 32));

        uint64_t ws_stop  =  (uint64_t)movemask32_ws_stop_avx2(v0)
                           | ((uint64_t)movemask32_ws_stop_avx2(v1)  << 32);

        uint64_t eol_stop =  (uint64_t)movemask32_eol_stop_avx2(v0)
                           | ((uint64_t)movemask32_eol_stop_avx2(v1) << 32);

        tape_whitespace[w] = ~ws_stop;
        tape_intoken[w] = ws_stop | eol_stop;
    }

    tape_whitespace[nwords] = 0;
    tape_intoken[nwords] = ~UINT64_C(0);
}
#endif

#ifdef SIMD_AVX512
/* ------------------------------------------------------- */
/* avx512                                                  */
/* ------------------------------------------------------- */

static void
classify_avx512(const char *data, size_t max,
                tokentape_t *tape_whitespace,
                tokentape_t *tape_intoken)
{
    size_t w, nwords;

    nwords = classify_word_count(max);

    for (w = 0; w < nwords; w++) {
        const char *p = data + (w << 6);
        __m512i v = _mm512_load_si512((const void *)p);

        __mmask64 sp = _mm512_cmpeq_epi8_mask(v, _mm512_set1_epi8(' '));
        __mmask64 tb = _mm512_cmpeq_epi8_mask(v, _mm512_set1_epi8('\t'));
        __mmask64 cr = _mm512_cmpeq_epi8_mask(v, _mm512_set1_epi8('\r'));
        __mmask64 lf = _mm512_cmpeq_epi8_mask(v, _mm512_set1_epi8('\n'));

        uint64_t ws_stop = (uint64_t)(sp | tb);
        uint64_t eol_stop = (uint64_t)(cr | lf);

        tape_whitespace[w] = ~ws_stop;
        tape_intoken[w] = ws_stop | eol_stop;
    }

    tape_whitespace[nwords] = 0;
    tape_intoken[nwords] = ~UINT64_C(0);
}
#endif

#if defined(SIMD_NEON32) || defined(SIMD_NEON64)
/* ------------------------------------------------------- */
/* neon helpers                                            */
/* ------------------------------------------------------- */

#if defined(SIMD_NEON64)
static always_inline unsigned
neon_movemask_u8(uint8x16_t cmp_ff00)
{
    uint8x16_t b = vshrq_n_u8(cmp_ff00, 7);
    const int8x8_t shifts = (int8x8_t){0,1,2,3,4,5,6,7};
    uint8x8_t lo = vshl_u8(vget_low_u8(b), shifts);
    uint8x8_t hi = vshl_u8(vget_high_u8(b), shifts);
    return (unsigned)vaddv_u8(lo) | ((unsigned)vaddv_u8(hi) << 8);
}
#else
static always_inline unsigned
neon_movemask_u8(uint8x16_t cmp_ff00)
{
    uint8_t t[16];
    unsigned mask = 0;
    unsigned i;
    vst1q_u8(t, cmp_ff00);
    for (i = 0; i < 16; i++)
        mask |= ((unsigned)(t[i] >> 7) & 1u) << i;
    return mask;
}
#endif

static always_inline unsigned
movemask16_ws_stop_neon(uint8x16_t v)
{
    uint8x16_t sp = vceqq_u8(v, vdupq_n_u8((uint8_t)' '));
    uint8x16_t tb = vceqq_u8(v, vdupq_n_u8((uint8_t)'\t'));
    return neon_movemask_u8(vorrq_u8(sp, tb));
}

static always_inline unsigned
movemask16_eol_stop_neon(uint8x16_t v)
{
    uint8x16_t cr = vceqq_u8(v, vdupq_n_u8((uint8_t)'\r'));
    uint8x16_t lf = vceqq_u8(v, vdupq_n_u8((uint8_t)'\n'));
    return neon_movemask_u8(vorrq_u8(cr, lf));
}
#endif

#ifdef SIMD_NEON32
/* ------------------------------------------------------- */
/* neon32                                                  */
/* ------------------------------------------------------- */

static void
classify_neon32(const char *data, size_t max,
                tokentape_t *tape_whitespace,
                tokentape_t *tape_intoken)
{
    size_t w, nwords;

    nwords = classify_word_count(max);

    for (w = 0; w < nwords; w++) {
        const uint8_t *p = (const uint8_t *)data + (w << 6);

        uint8x16_t v0 = vld1q_u8(p +  0);
        uint8x16_t v1 = vld1q_u8(p + 16);
        uint8x16_t v2 = vld1q_u8(p + 32);
        uint8x16_t v3 = vld1q_u8(p + 48);

        uint64_t ws_stop  =  (uint64_t)movemask16_ws_stop_neon(v0)
                           | ((uint64_t)movemask16_ws_stop_neon(v1)  << 16)
                           | ((uint64_t)movemask16_ws_stop_neon(v2)  << 32)
                           | ((uint64_t)movemask16_ws_stop_neon(v3)  << 48);

        uint64_t eol_stop =  (uint64_t)movemask16_eol_stop_neon(v0)
                           | ((uint64_t)movemask16_eol_stop_neon(v1) << 16)
                           | ((uint64_t)movemask16_eol_stop_neon(v2) << 32)
                           | ((uint64_t)movemask16_eol_stop_neon(v3) << 48);

        tape_whitespace[w] = maybe_reverse(~ws_stop);
        tape_intoken[w] = maybe_reverse(ws_stop | eol_stop);
    }

    tape_whitespace[nwords] = 0;
    tape_intoken[nwords] = ~UINT64_C(0);
}
#endif

#ifdef SIMD_NEON64
/* ------------------------------------------------------- */
/* neon64                                                  */
/* ------------------------------------------------------- */

static void
classify_neon64(const char *data, size_t max,
                tokentape_t *tape_whitespace,
                tokentape_t *tape_intoken)
{
    size_t w, nwords;

    nwords = classify_word_count(max);

    for (w = 0; w < nwords; w++) {
        const uint8_t *p = (const uint8_t *)data + (w << 6);

        uint8x16_t v0 = vld1q_u8(p +  0);
        uint8x16_t v1 = vld1q_u8(p + 16);
        uint8x16_t v2 = vld1q_u8(p + 32);
        uint8x16_t v3 = vld1q_u8(p + 48);

        uint64_t ws_stop  =  (uint64_t)movemask16_ws_stop_neon(v0)
                           | ((uint64_t)movemask16_ws_stop_neon(v1)  << 16)
                           | ((uint64_t)movemask16_ws_stop_neon(v2)  << 32)
                           | ((uint64_t)movemask16_ws_stop_neon(v3)  << 48);

        uint64_t eol_stop =  (uint64_t)movemask16_eol_stop_neon(v0)
                           | ((uint64_t)movemask16_eol_stop_neon(v1) << 16)
                           | ((uint64_t)movemask16_eol_stop_neon(v2) << 32)
                           | ((uint64_t)movemask16_eol_stop_neon(v3) << 48);

        tape_whitespace[w] = maybe_reverse(~ws_stop);
        tape_intoken[w] = maybe_reverse(ws_stop | eol_stop);
    }

    tape_whitespace[nwords] = 0;
    tape_intoken[nwords] = ~UINT64_C(0);
}
#endif

#ifdef SIMD_SVE2
/* ------------------------------------------------------- */
/* sve2                                                    */
/* ------------------------------------------------------- */

static always_inline uint64_t
sve_predicate_bits_64(svbool_t pred, size_t count)
{
    uint64_t out = 0;
    size_t i;

    for (i = 0; i < count; i++) {
        svbool_t one = svwhilelt_b8((uint64_t)i, (uint64_t)(i + 1));
        out |= (uint64_t)svptest_any(svptrue_b8(), svand_b_z(svptrue_b8(), pred, one)) << i;
    }

    return out;
}

static void
classify_sve2(const char *data, size_t max,
              tokentape_t *tape_whitespace,
              tokentape_t *tape_intoken)
{
    size_t nwords = classify_word_count(max);
    size_t w;
    size_t vl = svcntb();

    for (w = 0; w < nwords; w++) {
        const uint8_t *base = (const uint8_t *)data + (w << 6);
        uint64_t ws_stop = 0;
        uint64_t eol_stop = 0;
        size_t done = 0;

        while (done < 64u) {
            size_t chunk = 64u - done;
            if (chunk > vl)
                chunk = vl;

            {
                svbool_t pg = svwhilelt_b8((uint64_t)0, (uint64_t)chunk);
                svuint8_t v = svld1_u8(pg, base + done);

                svbool_t p_sp  = svcmpeq_n_u8(pg, v, (uint8_t)' ');
                svbool_t p_tb  = svcmpeq_n_u8(pg, v, (uint8_t)'\t');
                svbool_t p_cr  = svcmpeq_n_u8(pg, v, (uint8_t)'\r');
                svbool_t p_lf  = svcmpeq_n_u8(pg, v, (uint8_t)'\n');

                svbool_t p_ws  = svorr_b_z(pg, p_sp, p_tb);
                svbool_t p_eol = svorr_b_z(pg, p_cr, p_lf);

                ws_stop  |= sve_predicate_bits_64(p_ws, chunk)  << done;
                eol_stop |= sve_predicate_bits_64(p_eol, chunk) << done;
            }

            done += chunk;
        }

        tape_whitespace[w] = maybe_reverse(~ws_stop);
        tape_intoken[w] = maybe_reverse(ws_stop | eol_stop);
    }

    tape_whitespace[nwords] = 0;
    tape_intoken[nwords] = ~UINT64_C(0);
}
#endif

#ifdef SIMD_RISCVV
/* ------------------------------------------------------- */
/* riscvv                                                  */
/* ------------------------------------------------------- */

static always_inline uint64_t
rvv_mask_bits_64(vbool8_t pred, size_t count)
{
    uint64_t out = 0;
    size_t i;

    for (i = 0; i < count; i++) {
        vuint8m1_t idx = __riscv_vid_v_u8m1(count);
        vbool8_t one = __riscv_vmseq_vx_u8m1_b8(idx, (uint8_t)i, count);
        vbool8_t bit = __riscv_vmand_mm_b8(pred, one, count);
        out |= (uint64_t)(__riscv_vcpop_m_b8(bit, count) != 0) << i;
    }

    return out;
}

static void
classify_riscvv(const char *data, size_t max,
                tokentape_t *tape_whitespace,
                tokentape_t *tape_intoken)
{
    size_t nwords = classify_word_count(max);
    size_t w;

    for (w = 0; w < nwords; w++) {
        const uint8_t *base = (const uint8_t *)data + (w << 6);
        uint64_t ws_stop = 0;
        uint64_t eol_stop = 0;
        size_t done = 0;

        while (done < 64u) {
            size_t chunk = 64u - done;
            size_t vl = __riscv_vsetvl_e8m1(chunk);
            vuint8m1_t v = __riscv_vle8_v_u8m1(base + done, vl);

            vbool8_t p_sp  = __riscv_vmseq_vx_u8m1_b8(v, (uint8_t)' ', vl);
            vbool8_t p_tb  = __riscv_vmseq_vx_u8m1_b8(v, (uint8_t)'\t', vl);
            vbool8_t p_cr  = __riscv_vmseq_vx_u8m1_b8(v, (uint8_t)'\r', vl);
            vbool8_t p_lf  = __riscv_vmseq_vx_u8m1_b8(v, (uint8_t)'\n', vl);

            vbool8_t p_ws  = __riscv_vmor_mm_b8(p_sp, p_tb, vl);
            vbool8_t p_eol = __riscv_vmor_mm_b8(p_cr, p_lf, vl);

            ws_stop  |= rvv_mask_bits_64(p_ws, vl)  << done;
            eol_stop |= rvv_mask_bits_64(p_eol, vl) << done;

            done += vl;
        }

        tape_whitespace[w] = ~ws_stop;
        tape_intoken[w] = ws_stop | eol_stop;
    }

    tape_whitespace[nwords] = 0;
    tape_intoken[nwords] = ~UINT64_C(0);
}
#endif

/* ------------------------------------------------------- */
/* init                                                    */
/* ------------------------------------------------------- */


void
zone_fast_classify_init(int backend)
{
    switch (backend) {
    case SIMD_AUTO:
        zone_fast_classify_init(simd_get_best());
        return;

#ifdef SIMD_SCALAR1
    case SIMD_SCALAR1:
        zone_fast_classify = classify_scalar1;
        return;
#endif

#ifdef SIMD_SCALAR2
    case SIMD_SCALAR2:
        zone_fast_classify = classify_scalar2;
        return;
#endif

#ifdef SIMD_SWAR
    case SIMD_SWAR:
        zone_fast_classify = classify_swar;
        return;
#endif

#ifdef SIMD_SSE2
    case SIMD_SSE2:
        zone_fast_classify = classify_sse2;
        return;
#endif

#ifdef SIMD_SSE42
    case SIMD_SSE42:
        zone_fast_classify = classify_sse42;
        return;
#endif

#ifdef SIMD_AVX2
    case SIMD_AVX2:
        zone_fast_classify = classify_avx2;
        return;
#endif

#ifdef SIMD_AVX512
    case SIMD_AVX512:
        zone_fast_classify = classify_avx512;
        return;
#endif

#ifdef SIMD_NEON32
    case SIMD_NEON32:
        zone_fast_classify = classify_neon32;
        return;
#endif

#ifdef SIMD_NEON64
    case SIMD_NEON64:
        zone_fast_classify = classify_neon64;
        return;
#endif

#ifdef SIMD_SVE2
    case SIMD_SVE2:
        zone_fast_classify = classify_sve2;
        return;
#endif

#ifdef SIMD_RISCVV
    case SIMD_RISCVV:
        zone_fast_classify = classify_riscvv;
        return;
#endif

    default:
        zone_fast_classify = classify_scalar2;
        return;
    }
}

/* ------------------------------------------------------- */
/* quicktest                                               */
/* ------------------------------------------------------- */

struct length_expect {
    size_t offset;
    size_t whitespace_len;
    size_t intoken_len;
};

static int
quicktest_one_backend(int backend)
{
    enum { BUFSIZE = 256, TAPEWORDS = 20 };
    unsigned char buf[BUFSIZE];
    tokentape_t ws[TAPEWORDS];
    tokentape_t tok[TAPEWORDS];
    static const char prefix[] =
        "AB C\tD\rE\n"
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
        "qrstuv wx\n"
        "yZZZZZZZZZZZZZZZZZ K";
    static const char pad[] =
        "\n \n \n"
        "                                                                ";
    static const struct length_expect expects[] = {
        {  9, 0, 57 },
        {  0, 0,  2 },
        {  2, 1,  0 },
        {  3, 0,  1 },
        {  4, 1,  0 },
        {  5, 0,  1 },
        {  6, 0,  0 },
        {  7, 0,  1 },
        {  8, 0,  0 },
        {  9, 0, 57 },
        { 60, 0,  6 },
        { 66, 1,  0 },
        { 67, 0,  2 },
        { 69, 0,  0 },
        { 70, 0, 18 },
        { 88, 1,  0 },
        { 89, 0,  1 },
        { 96, 96,  0 }
    };
    size_t i;
    size_t max = sizeof(prefix) - 1;

    memset(buf, 'X', sizeof(buf));
    memcpy(buf, prefix, sizeof(prefix) - 1);
    memcpy(buf + max, pad, sizeof(pad) - 1);
    memset(buf + max + sizeof(pad) - 1, ' ', BUFSIZE - (max + sizeof(pad) - 1));

    zone_fast_classify_init(backend);
    if (!zone_fast_classify)
        return 1000 + backend;

    zone_fast_classify((const char *)buf, max, ws, tok);

    /*for (i = 0; i < max + 64; i++) {
        unsigned c = buf[i];
        unsigned expect_ws = (unsigned)(c != ' ' && c != '\t');
        unsigned expect_tok = (unsigned)(c == ' ' || c == '\t' || c == '\r' || c == '\n');
        unsigned got_ws = (unsigned)((ws[i >> 6] >> (i & 63)) & 1u);
        unsigned got_tok = (unsigned)((tok[i >> 6] >> (i & 63)) & 1u);

        if (got_ws != expect_ws)
            return 2000 + (int)i;
        if (got_tok != expect_tok)
            return 3000 + (int)i;
    }*/

    for (i = 0; i < sizeof(expects) / sizeof(expects[0]); i++) {
        size_t offset = expects[i].offset;
        size_t got_ws_len = classified_length(ws, offset);
        size_t got_tok_len = classified_length(tok, offset);

        if (got_ws_len != expects[i].whitespace_len)
            return 4000 + (int)i * 2;
        if (got_tok_len != expects[i].intoken_len)
            return 4001 + (int)i * 2;
    }

    return 0;
}

int
zone_fast_classify_quicktest(void)
{
    int err = 0;
    
    for (unsigned backend = 0; backend < SIMD_MAX; backend++) {
        int x = quicktest_one_backend(backend);
        if (x)
            fprintf(stderr, "[-] selftest.classify(%s) failed\n", simd_name(backend));
        err += x;
    }
    
    return err;
}
