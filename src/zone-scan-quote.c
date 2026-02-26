// zone-scan-quote.c
//
// Contract (per caller):
// - There is always at least one trigger byte ahead (at minimum '\n').
// - The buffer is padded so we may read at least 64 bytes past (data+len)
//   without fault.
// Therefore: no length checks needed; we can scan until the first trigger.
//
// Trigger bytes:  '"', '\\', '\n'
// Return: number of bytes consumed before the first trigger.
#include "zone-scan.h"
#include <string.h>
#include <stdio.h>
#include <assert.h>

/* -------------------------------- scalar ---------------------------------- */
static inline size_t
scan_quote_scalar(const char *data, size_t i, size_t len_ignored)
{
    (void)len_ignored;
    for (;;) {
        unsigned char c = (unsigned char)data[i];
        if (c == (unsigned char)'"' || c == (unsigned char)'\\' || c == (unsigned char)'\n')
            return i;
        i++;
    }
}

/* --------------------------------- SWAR ----------------------------------- */
static inline uint64_t zone_repeat_u8(uint8_t c) { return (uint64_t)c * 0x0101010101010101ULL; }

static inline uint64_t
zone_has_eq_u8(uint64_t x, uint8_t c)
{
    // 0x80 in each byte lane where x-byte == c, else 0.
    uint64_t y = x ^ zone_repeat_u8(c);
    return (y - 0x0101010101010101ULL) & ~y & 0x8080808080808080ULL;
}

static inline size_t
scan_quote_swar(const char *data, size_t i, size_t len_ignored)
{
    (void)len_ignored;

    for (;;) {
        uint64_t w;
        __builtin_memcpy(&w, data + i, 8);

        uint64_t m =
            zone_has_eq_u8(w, (uint8_t)'"') |
            zone_has_eq_u8(w, (uint8_t)'\\') |
            zone_has_eq_u8(w, (uint8_t)'\n');

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
scan_quote_sse2(const char *data, size_t i, size_t len_ignored)
{
    (void)len_ignored;

    const __m128i q  = _mm_set1_epi8('"');
    const __m128i bs = _mm_set1_epi8('\\');
    const __m128i nl = _mm_set1_epi8('\n');

    for (;;) {
        __m128i v = _mm_loadu_si128((const __m128i *)(const void *)(data + i));

        __m128i m = _mm_or_si128(
                        _mm_or_si128(_mm_cmpeq_epi8(v, q), _mm_cmpeq_epi8(v, bs)),
                        _mm_cmpeq_epi8(v, nl));

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
  #include <nmmintrin.h>  // _mm_cmpestri + _SIDD_*
  #include <emmintrin.h>  // _mm_loadu_si128

static size_t
scan_quote_sse42(const char *data, size_t i, size_t len_ignored)
{
    (void)len_ignored;

    // SSE4.2 text/string instruction via PCMPISTRI/PCMPIESTRI:
    // Find first byte in haystack that equals any byte in needle set.
    const __m128i needle = _mm_setr_epi8('"', '\\', '\n',
                                         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    const int needle_len = 3;
#define mode _SIDD_UBYTE_OPS | _SIDD_CMP_EQUAL_ANY | _SIDD_LEAST_SIGNIFICANT

    for (;;) {
        __m128i hay = _mm_loadu_si128((const __m128i *)(const void *)(data + i));

        // Returns [0..16]; 16 means "no match in these 16 bytes".
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
scan_quote_avx2(const char *data, size_t i, size_t len_ignored)
{
    (void)len_ignored;

    const __m256i q  = _mm256_set1_epi8('"');
    const __m256i bs = _mm256_set1_epi8('\\');
    const __m256i nl = _mm256_set1_epi8('\n');

    for (;;) {
        __m256i v = _mm256_loadu_si256((const __m256i *)(const void *)(data + i));

        __m256i m = _mm256_or_si256(
                        _mm256_or_si256(_mm256_cmpeq_epi8(v, q), _mm256_cmpeq_epi8(v, bs)),
                        _mm256_cmpeq_epi8(v, nl));

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
scan_quote_avx512(const char *data, size_t i, size_t len_ignored)
{
    (void)len_ignored;

    const __m512i q  = _mm512_set1_epi8('"');
    const __m512i bs = _mm512_set1_epi8('\\');
    const __m512i nl = _mm512_set1_epi8('\n');

    for (;;) {
        __m512i v = _mm512_loadu_si512((const void *)(data + i));

        __mmask64 m =
            _mm512_cmpeq_epi8_mask(v, q) |
            _mm512_cmpeq_epi8_mask(v, bs) |
            _mm512_cmpeq_epi8_mask(v, nl);

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

static inline int
zone_neon_any_match(uint8x16_t m)
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
scan_quote_neon(const char *data, size_t i, size_t len_ignored)
{
    (void)len_ignored;

    const uint8x16_t q  = vdupq_n_u8((uint8_t)'"');
    const uint8x16_t bs = vdupq_n_u8((uint8_t)'\\');
    const uint8x16_t nl = vdupq_n_u8((uint8_t)'\n');

    for (;;) {
        uint8x16_t v = vld1q_u8((const uint8_t *)(const void *)(data + i));

        uint8x16_t m = vorrq_u8(
                           vorrq_u8(vceqq_u8(v, q), vceqq_u8(v, bs)),
                           vceqq_u8(v, nl));

        if (zone_neon_any_match(m)) {
            // Rare path: pinpoint the first hit.
            for (unsigned j = 0; j < 16; j++) {
                unsigned char c = (unsigned char)data[i + j];
                if (c == (unsigned char)'"' || c == (unsigned char)'\\' || c == (unsigned char)'\n')
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
scan_quote_sve2(const char *data, size_t i, size_t len_ignored)
{
    (void)len_ignored;

    const uint8_t cq  = (uint8_t)'"';
    const uint8_t cbs = (uint8_t)'\\';
    const uint8_t cnl = (uint8_t)'\n';

    for (;;) {
        // Full predicate (we're allowed to read past end due to padding).
        // Using full-width pg keeps the loop simple and fast.
        svbool_t pg = svptrue_b8();
        svuint8_t v = svld1_u8(pg, (const uint8_t *)(const void *)(data + i));

        svbool_t m =
            svorr_b_z(pg, svcmpeq_n_u8(pg, v, cq),  svcmpeq_n_u8(pg, v, cbs));
        m = svorr_b_z(pg, m, svcmpeq_n_u8(pg, v, cnl));

        if (svptest_any(pg, m)) {
            svbool_t prefix = svbrkb_z(pg, m);           // lanes before first match
            uint64_t idx = svcntp_b8(pg, prefix);        // count lanes before match
            return i + (size_t)idx;
        }

        i += (size_t)svcntb(); // full vector length in bytes
    }
}
#endif /* SIMD_SVE2 */

/* -------------------------------- RISC-V V -------------------------------- */
#ifdef SIMD_RISCVV
  #include <riscv_vector.h>

static size_t
scan_quote_riscvv(const char *data, size_t i, size_t len_ignored)
{
    (void)len_ignored;

    for (;;) {
        // We're allowed to read past end, so just use max VL each time.
        size_t vl = vsetvlmax_e8m1();

        vuint8m1_t v = vle8_v_u8m1((const uint8_t *)(const void *)(data + i), vl);

        vbool8_t m =
            vmor_mm(
                vmor_mm(vmseq_vx_u8m1_b8(v, (uint8_t)'"',  vl),
                        vmseq_vx_u8m1_b8(v, (uint8_t)'\\', vl), vl),
                vmseq_vx_u8m1_b8(v, (uint8_t)'\n', vl), vl);

        long idx = vfirst_m_b8(m, vl);
        if (idx >= 0)
            return i + (size_t)idx;

        i += vl;
    }
}
#endif /* SIMD_RISCVV */

static size_t (*scanner)(const char *data, size_t offset, size_t len) = scan_quote_scalar;

size_t zone_scan_quote(const char *data, size_t offset, size_t max) {
    
    for (;;) {
        
        /* fast SIMD scan */
        offset = scanner(data, offset, max);
        
        char c = data[offset];
        
        if (c == '\"') {
            return offset; /* SUCCESS! */
        }
        
        if (c == '\\') {
            offset = zone_scan_escape(data, offset, max);
            if (offset >= max)
                return max + 1;
            continue;
        } else {
            assert(c == '\n');
            return offset;
        }
    }
    return max + 1; /* error */
}



void zone_scan_quote_init(simd_backend_t backend) {
    switch (backend) {
    case SIMD_AUTO:
        zone_scan_quote_init(simd_get_best());
        break;
    case SIMD_SCALAR:
        scanner = scan_quote_scalar;
        break;
    case SIMD_SWAR:
        scanner = scan_quote_swar;
        break;
#if defined(SIMD_SSE2)
    case SIMD_SSE2:
        scanner = scan_quote_sse2;
        break;
#endif
#if defined(SIMD_SSE42)
    case SIMD_SSE42:
        scanner = scan_quote_sse42;
        break;
#endif
#if defined(SIMD_AVX2)
    case SIMD_AVX2:
        scanner = scan_quote_avx2;
        break;
#endif
#if defined(SIMD_AVX512)
    case SIMD_AVX512:
        scanner = scan_quote_avx512;
        break;
#endif
#if defined(SIMD_NEON)
    case SIMD_NEON:
        scanner = scan_quote_neon;
        break;
#endif
#if defined(SIMD_SVE2)
    case SIMD_SVE2:
        scanner = scan_quote_sve2;
        break;
#endif
#if defined(SIMD_RISCVV)
    case SIMD_RISCVV:
        scanner = scan_quote_riscvv;
        break;
#endif
    default:
        scanner = scan_quote_scalar;
        break;
    }
}

static struct testcases {
    const char *input;
    unsigned out_len;
} tests[] = {
    {"abcd", 4},
    
    {"abcd\\\nxyz\"", 11},
    {"abcd\\xyz\"", 8},
    {"abcd", 4},
    {"abcd\"", 4},
    {"abcd\\", 6},
    {"abcd\\1\"", 6},
    {"abcd\\12\"", 7},
    {"abcd\\123\"", 8},
    {"abcd\\123xyz", 11},
    {"abcd\\123xyz\"", 11},
    {"abcd\\12xyz\"", 10},
    {"abcd\\1xyz\"", 9},
    {0,0}
};

int zone_scan_quote_quicktest(void) {
    int err = 0;
    char buf[1024];
    memset(buf, '\n', sizeof(buf));
    
    for (int i=0; tests[i].input; i++) {
        size_t in_len = strlen(tests[i].input);
        
        memcpy(buf, tests[i].input, in_len);
        buf[in_len] = '\n'; /* always line terminate past the end */
        
        size_t out_len = zone_scan_quote(buf, 0, in_len);
        if (out_len != tests[i].out_len) {
            fprintf(stderr, "[-] scan.quote(): test %d failed, len=%u\n", i, (unsigned)out_len);
            err++;
        }
    }
    
    return err;
}
