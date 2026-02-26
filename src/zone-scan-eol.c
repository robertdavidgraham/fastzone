
// zone-scan-eol.c
//
// Contract (per caller):
// - There is always at least one '\n' ahead.
// - The buffer is padded so we may read at least 64 bytes past the logical end.
// Therefore: no bounds checks needed; we scan until '\n'.
//
// Trigger byte: '\n' (0x0A)
// Return: index of the first '\n' relative to data.
#include "zone-scan.h"
#include <string.h>
#include <stdio.h>
#include <assert.h>

/* -------------------------------- scalar ---------------------------------- */
static inline size_t
scan_scalar(const char *data, size_t i, size_t len_ignored)
{
    (void)len_ignored;
    for (;;) {
        if ((unsigned char)data[i] == (unsigned char)'\n')
            return i;
        i++;
    }
}

/* --------------------------------- SWAR ----------------------------------- */
static inline uint64_t zone_repeat_u8(uint8_t c) { return (uint64_t)c * 0x0101010101010101ULL; }

static inline uint64_t
zone_has_eq_u8(uint64_t x, uint8_t c)
{
    uint64_t y = x ^ zone_repeat_u8(c);
    return (y - 0x0101010101010101ULL) & ~y & 0x8080808080808080ULL;
}

static inline size_t
scan_swar(const char *data, size_t i, size_t len_ignored)
{
    (void)len_ignored;
    for (;;) {
        uint64_t w;
        __builtin_memcpy(&w, data + i, 8);

        uint64_t m = zone_has_eq_u8(w, (uint8_t)'\n');
        if (m) {
            unsigned bit = (unsigned)__builtin_ctzll(m);
            return i + (size_t)(bit >> 3);
        }

        i += 8;
    }
}

/* --------------------------------- SSE2 ----------------------------------- */
#ifdef SIMD_SSE2
  #include <emmintrin.h>

static size_t
scan_sse2(const char *data, size_t i, size_t len_ignored)
{
    (void)len_ignored;

    const __m128i nl = _mm_set1_epi8('\n');

    for (;;) {
        __m128i v = _mm_loadu_si128((const __m128i *)(const void *)(data + i));
        __m128i m = _mm_cmpeq_epi8(v, nl);

        unsigned mask = (unsigned)_mm_movemask_epi8(m);
        if (mask) {
            unsigned idx = (unsigned)__builtin_ctz(mask);
            return i + (size_t)idx;
        }

        i += 16;
    }
}
#endif /* SIMD_SSE2 */

/* -------------------------------- SSE4.2 ---------------------------------- */
#ifdef SIMD_SSE42
  #include <nmmintrin.h>
  #include <emmintrin.h>

static size_t
scan_sse42(const char *data, size_t i, size_t len_ignored)
{
    (void)len_ignored;

    const __m128i needle = _mm_set1_epi8('\n');
    const int needle_len = 1;
#define mode  _SIDD_UBYTE_OPS | _SIDD_CMP_EQUAL_ANY | _SIDD_LEAST_SIGNIFICANT

    for (;;) {
        __m128i hay = _mm_loadu_si128((const __m128i *)(const void *)(data + i));
        int idx = _mm_cmpestri(needle, needle_len, hay, 16, mode);
        if (idx != 16)
            return i + (size_t)idx;

        i += 16;
    }
}
#endif /* SIMD_SSE42 */

/* --------------------------------- AVX2 ----------------------------------- */
#ifdef SIMD_AVX2
  #include <immintrin.h>

static size_t
scan_avx2(const char *data, size_t i, size_t len_ignored)
{
    (void)len_ignored;

    const __m256i nl = _mm256_set1_epi8('\n');

    for (;;) {
        __m256i v = _mm256_loadu_si256((const __m256i *)(const void *)(data + i));
        __m256i m = _mm256_cmpeq_epi8(v, nl);

        unsigned mask = (unsigned)_mm256_movemask_epi8(m);
        if (mask) {
            unsigned idx = (unsigned)__builtin_ctz(mask);
            return i + (size_t)idx;
        }

        i += 32;
    }
}
#endif /* SIMD_AVX2 */

/* -------------------------------- AVX-512 --------------------------------- */
#ifdef SIMD_AVX512
  #include <immintrin.h>

static size_t
scan_avx512(const char *data, size_t i, size_t len_ignored)
{
    (void)len_ignored;

    const __m512i nl = _mm512_set1_epi8('\n');

    for (;;) {
        __m512i v = _mm512_loadu_si512((const void *)(data + i));
        __mmask64 m = _mm512_cmpeq_epi8_mask(v, nl);

        if (m) {
            unsigned idx = (unsigned)__builtin_ctzll((unsigned long long)m);
            return i + (size_t)idx;
        }

        i += 64;
    }
}
#endif /* SIMD_AVX512 */

/* --------------------------------- NEON ----------------------------------- */
#ifdef SIMD_NEON
  #include <arm_neon.h>

static inline int zone_neon_any(uint8x16_t m)
{
#if defined(__aarch64__)
    return (int)(vmaxvq_u8(m) != 0);
#else
    uint8x8_t lo = vget_low_u8(m);
    uint8x8_t hi = vget_high_u8(m);
    uint8x8_t o = vorr_u8(lo, hi);
    o = vorr_u8(o, vext_u8(o, o, 4));
    o = vorr_u8(o, vext_u8(o, o, 2));
    o = vorr_u8(o, vext_u8(o, o, 1));
    return (int)(vget_lane_u8(o, 0) != 0);
#endif
}

static size_t
scan_neon(const char *data, size_t i, size_t len_ignored)
{
    (void)len_ignored;

    const uint8x16_t nl = vdupq_n_u8((uint8_t)'\n');

    for (;;) {
        uint8x16_t v = vld1q_u8((const uint8_t *)(const void *)(data + i));
        uint8x16_t m = vceqq_u8(v, nl);

        if (zone_neon_any(m)) {
            for (unsigned j = 0; j < 16; j++) {
                if ((unsigned char)data[i + j] == (unsigned char)'\n')
                    return i + (size_t)j;
            }
        }

        i += 16;
    }
}
#endif /* SIMD_NEON */

/* --------------------------------- SVE2 ----------------------------------- */
#ifdef SIMD_SVE2
  #include <arm_sve.h>

static size_t
scan_sve2(const char *data, size_t i, size_t len_ignored)
{
    (void)len_ignored;

    const uint8_t c = (uint8_t)'\n';

    for (;;) {
        svbool_t pg = svptrue_b8();
        svuint8_t v = svld1_u8(pg, (const uint8_t *)(const void *)(data + i));

        svbool_t m = svcmpeq_n_u8(pg, v, c);
        if (svptest_any(pg, m)) {
            svbool_t prefix = svbrkb_z(pg, m);
            uint64_t idx = svcntp_b8(pg, prefix);
            return i + (size_t)idx;
        }

        i += (size_t)svcntb();
    }
}
#endif /* SIMD_SVE2 */

/* -------------------------------- RISC-V V -------------------------------- */
#ifdef SIMD_RISCVV
  #include <riscv_vector.h>

static size_t
scan_riscvv(const char *data, size_t i, size_t len_ignored)
{
    (void)len_ignored;

    for (;;) {
        size_t vl = vsetvlmax_e8m1();

        vuint8m1_t v = vle8_v_u8m1((const uint8_t *)(const void *)(data + i), vl);
        vbool8_t m = vmseq_vx_u8m1_b8(v, (uint8_t)'\n', vl);

        long idx = vfirst_m_b8(m, vl);
        if (idx >= 0)
            return i + (size_t)idx;

        i += vl;
    }
}
#endif /* SIMD_RISCVV */


#define scanner zone_scan_eol
size_t (*zone_scan_eol)(const char *data, size_t offset, size_t len) = scan_scalar;


void zone_scan_eol_init(simd_backend_t backend) {
    switch (backend) {
    case SIMD_AUTO:
        zone_scan_eol_init(simd_get_best());
        break;
    case SIMD_SCALAR:
        scanner = scan_scalar;
        break;
    case SIMD_SWAR:
        scanner = scan_swar;
        break;
#if defined(SIMD_SSE2)
    case SIMD_SSE2:
        scanner = scan_sse2;
        break;
#endif
#if defined(SIMD_SSE42)
    case SIMD_SSE42:
        scanner = scan_sse42;
        break;
#endif
#if defined(SIMD_AVX2)
    case SIMD_AVX2:
        scanner = scan_avx2;
        break;
#endif
#if defined(SIMD_AVX512)
    case SIMD_AVX512:
        scanner = scan_avx512;
        break;
#endif
#if defined(SIMD_NEON)
    case SIMD_NEON:
        scanner = scan_neon;
        break;
#endif
#if defined(SIMD_SVE2)
    case SIMD_SVE2:
        scanner = scan_sve2;
        break;
#endif
#if defined(SIMD_RISCVV)
    case SIMD_RISCVV:
        scaner = scan_riscvv;
        break;
#endif
    default:
        scanner = scan_scalar;
        break;
    }
}

static struct testcases {
    const char *input;
    unsigned out_len;
} tests[] = {
    {"abcd\\\nxyz\"", 5},
    {"abcd\\xyz\"", 9},
    {"abcd", 4},
    {"abcd\"", 5},
    {0,0}
};

int zone_scan_eol_quicktest(void) {
    int err = 0;
    char buf[1024];
    memset(buf, '\n', sizeof(buf));
    
    for (int i=0; tests[i].input; i++) {
        size_t in_len = strlen(tests[i].input);
        
        memcpy(buf, tests[i].input, in_len);
        buf[in_len] = '\n'; /* always line terminate past the end */
        
        size_t out_len = zone_scan_eol(buf, 0, in_len);
        if (out_len != tests[i].out_len) {
            fprintf(stderr, "[-] scan.eol(): test %d failed, len=%u\n", i, (unsigned)out_len);
            err++;
        }
    }
    
    return err;
}
