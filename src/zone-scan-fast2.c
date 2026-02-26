// zone-scan-fast2.c
//
// Contract (per caller):
// - There is always at least one trigger byte ahead (at minimum '\n').
// - The buffer is padded so we may read at least 64 bytes past the logical end.
// Therefore: no bounds checks needed; we scan until a trigger.
//
// Trigger bytes:
//   '(' , ')' , ';' , '\\' , '"' , '\n' (0x0A)
//
// API you asked for:
//   size_t zone_scan_fast2(const char *data, size_t i, size_t len_ignored);
//
// - All SIMD variants are file-local (static) and have simple names: scan_sse2,
//   scan_sse42, scan_avx2, ...
// - Scalar + SWAR are always compiled (no #ifdef). SIMD is behind SIMD_*.
// - No runtime dispatch here; you’ll do that elsewhere.
#include "util-simd.h"
#include "zone-scan.h"
#include "util-ctz.h"
#include <string.h> // memcpy

/* -------------------------------- scalar ---------------------------------- */
static inline size_t
scan_scalar(const char *data, size_t i, size_t max)
{
    for (;;) {
        unsigned char c = (unsigned char)data[i];
        if (c == (unsigned char)'(' ||
            c == (unsigned char)')' ||
            c == (unsigned char)';' ||
            c == (unsigned char)'\\' ||
            c == (unsigned char)'"' ||
            c == (unsigned char)'\n')
            return i;
        i++;
    }
}

/* --------------------------------- SWAR ----------------------------------- */
static inline uint64_t repeat_u8(uint8_t c) { return (uint64_t)c * 0x0101010101010101ULL; }

static inline uint64_t
has_eq_u8(uint64_t x, uint8_t c)
{
    // 0x80 in each byte lane where x-byte == c, else 0.
    uint64_t y = x ^ repeat_u8(c);
    return (y - 0x0101010101010101ULL) & ~y & 0x8080808080808080ULL;
}

static inline size_t
scan_swar(const char *data, size_t i, size_t max)
{
    for (;;) {
        uint64_t w;
        memcpy(&w, data + i, 8);

        uint64_t m =
            has_eq_u8(w, (uint8_t)'(') |
            has_eq_u8(w, (uint8_t)')') |
            has_eq_u8(w, (uint8_t)';') |
            has_eq_u8(w, (uint8_t)'\\') |
            has_eq_u8(w, (uint8_t)'"') |
            has_eq_u8(w, (uint8_t)'\n');

        if (m) {
            unsigned bit = ctz64(m);
            return i + (size_t)(bit >> 3);
        }

        i += 8;
    }
}

/* --------------------------------- SSE2 ----------------------------------- */
#ifdef SIMD_SSE2
  #include <emmintrin.h>

static size_t
scan_sse2(const char *data, size_t i, size_t max)
{
    const __m128i c_lp = _mm_set1_epi8('(');
    const __m128i c_rp = _mm_set1_epi8(')');
    const __m128i c_sc = _mm_set1_epi8(';');
    const __m128i c_bs = _mm_set1_epi8('\\');
    const __m128i c_q  = _mm_set1_epi8('"');
    const __m128i c_nl = _mm_set1_epi8('\n');

    for (;;) {
        __m128i v = _mm_loadu_si128((const __m128i *)(const void *)(data + i));

        __m128i m =
            _mm_or_si128(
                _mm_or_si128(_mm_cmpeq_epi8(v, c_lp), _mm_cmpeq_epi8(v, c_rp)),
                _mm_or_si128(
                    _mm_or_si128(_mm_cmpeq_epi8(v, c_sc), _mm_cmpeq_epi8(v, c_bs)),
                    _mm_or_si128(_mm_cmpeq_epi8(v, c_q),  _mm_cmpeq_epi8(v, c_nl))));

        unsigned mask = (unsigned)_mm_movemask_epi8(m);
        if (mask) {
            unsigned idx = ctz32(mask);
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
scan_sse42(const char *data, size_t i, size_t max)
{
    // Use SSE4.2 text/string instruction (PCMPISTRI via _mm_cmpestri):
    // Find first haystack byte equal to any needle byte.
    const __m128i needle = _mm_setr_epi8('(', ')', ';', '\\', '"', '\n',
                                         0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    const int needle_len = 6;
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
scan_avx2(const char *data, size_t i, size_t max)
{
    const __m256i c_lp = _mm256_set1_epi8('(');
    const __m256i c_rp = _mm256_set1_epi8(')');
    const __m256i c_sc = _mm256_set1_epi8(';');
    const __m256i c_bs = _mm256_set1_epi8('\\');
    const __m256i c_q  = _mm256_set1_epi8('"');
    const __m256i c_nl = _mm256_set1_epi8('\n');

    for (;;) {
        __m256i v = _mm256_loadu_si256((const __m256i *)(const void *)(data + i));

        __m256i m =
            _mm256_or_si256(
                _mm256_or_si256(_mm256_cmpeq_epi8(v, c_lp), _mm256_cmpeq_epi8(v, c_rp)),
                _mm256_or_si256(
                    _mm256_or_si256(_mm256_cmpeq_epi8(v, c_sc), _mm256_cmpeq_epi8(v, c_bs)),
                    _mm256_or_si256(_mm256_cmpeq_epi8(v, c_q),  _mm256_cmpeq_epi8(v, c_nl))));

        unsigned mask = (unsigned)_mm256_movemask_epi8(m);
        if (mask) {
            unsigned idx = ctz32(mask);
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
scan_avx512(const char *data, size_t i, size_t max)
{
    const __m512i c_lp = _mm512_set1_epi8('(');
    const __m512i c_rp = _mm512_set1_epi8(')');
    const __m512i c_sc = _mm512_set1_epi8(';');
    const __m512i c_bs = _mm512_set1_epi8('\\');
    const __m512i c_q  = _mm512_set1_epi8('"');
    const __m512i c_nl = _mm512_set1_epi8('\n');

    for (;;) {
        __m512i v = _mm512_loadu_si512((const void *)(data + i));

        __mmask64 m =
            _mm512_cmpeq_epi8_mask(v, c_lp) |
            _mm512_cmpeq_epi8_mask(v, c_rp) |
            _mm512_cmpeq_epi8_mask(v, c_sc) |
            _mm512_cmpeq_epi8_mask(v, c_bs) |
            _mm512_cmpeq_epi8_mask(v, c_q)  |
            _mm512_cmpeq_epi8_mask(v, c_nl);

        if (m) {
            unsigned idx = ctz64((uint64_t)m);
            return i + (size_t)idx;
        }

        i += 64;
    }
}
#endif /* SIMD_AVX512 */

/* --------------------------------- NEON ----------------------------------- */
#ifdef SIMD_NEON
  #include <arm_neon.h>

static inline int neon_any(uint8x16_t m)
{
  #if defined(__aarch64__) || defined(_M_ARM64)
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
scan_neon(const char *data, size_t i, size_t max)
{
    const uint8x16_t c_lp = vdupq_n_u8((uint8_t)'(');
    const uint8x16_t c_rp = vdupq_n_u8((uint8_t)')');
    const uint8x16_t c_sc = vdupq_n_u8((uint8_t)';');
    const uint8x16_t c_bs = vdupq_n_u8((uint8_t)'\\');
    const uint8x16_t c_q  = vdupq_n_u8((uint8_t)'"');
    const uint8x16_t c_nl = vdupq_n_u8((uint8_t)'\n');

    for (;;) {
        uint8x16_t v = vld1q_u8((const uint8_t *)(const void *)(data + i));

        uint8x16_t m =
            vorrq_u8(
                vorrq_u8(vceqq_u8(v, c_lp), vceqq_u8(v, c_rp)),
                vorrq_u8(
                    vorrq_u8(vceqq_u8(v, c_sc), vceqq_u8(v, c_bs)),
                    vorrq_u8(vceqq_u8(v, c_q),  vceqq_u8(v, c_nl))));

        if (neon_any(m)) {
            // rare pinpoint
            for (unsigned j = 0; j < 16; j++) {
                unsigned char c = (unsigned char)data[i + j];
                if (c == (unsigned char)'(' || c == (unsigned char)')' ||
                    c == (unsigned char)';' || c == (unsigned char)'\\' ||
                    c == (unsigned char)'"' || c == (unsigned char)'\n')
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
scan_sve2(const char *data, size_t i, size_t max)
{
    const uint8_t c_lp = (uint8_t)'(';
    const uint8_t c_rp = (uint8_t)')';
    const uint8_t c_sc = (uint8_t)';';
    const uint8_t c_bs = (uint8_t)'\\';
    const uint8_t c_q  = (uint8_t)'"';
    const uint8_t c_nl = (uint8_t)'\n';

    for (;;) {
        svbool_t pg = svptrue_b8();
        svuint8_t v = svld1_u8(pg, (const uint8_t *)(const void *)(data + i));

        svbool_t m = svcmpeq_n_u8(pg, v, c_lp);
        m = svorr_b_z(pg, m, svcmpeq_n_u8(pg, v, c_rp));
        m = svorr_b_z(pg, m, svcmpeq_n_u8(pg, v, c_sc));
        m = svorr_b_z(pg, m, svcmpeq_n_u8(pg, v, c_bs));
        m = svorr_b_z(pg, m, svcmpeq_n_u8(pg, v, c_q));
        m = svorr_b_z(pg, m, svcmpeq_n_u8(pg, v, c_nl));

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
scan_riscvv(const char *data, size_t i, size_t max)
{
    for (;;) {
        size_t vl = vsetvlmax_e8m1();
        vuint8m1_t v = vle8_v_u8m1((const uint8_t *)(const void *)(data + i), vl);

        vbool8_t m = vmseq_vx_u8m1_b8(v, (uint8_t)'(', vl);
        m = vmor_mm(m, vmseq_vx_u8m1_b8(v, (uint8_t)')',  vl), vl);
        m = vmor_mm(m, vmseq_vx_u8m1_b8(v, (uint8_t)';',  vl), vl);
        m = vmor_mm(m, vmseq_vx_u8m1_b8(v, (uint8_t)'\\', vl), vl);
        m = vmor_mm(m, vmseq_vx_u8m1_b8(v, (uint8_t)'"',  vl), vl);
        m = vmor_mm(m, vmseq_vx_u8m1_b8(v, (uint8_t)'\n', vl), vl);

        long idx = vfirst_m_b8(m, vl);
        if (idx >= 0)
            return i + (size_t)idx;

        i += vl;
    }
}
#endif /* SIMD_RISCVV */


#define scanner zone_scan_fast
size_t (*zone_scan_fast2)(const char *data, size_t offset, size_t len) = scan_scalar;

void zone_scan_fast2_init(simd_backend_t backend) {
    switch (backend) {
    case SIMD_AUTO:
        zone_scan_fast2_init(simd_get_best());
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
        scanner = scan_riscvv;
        break;
#endif
    default:
        scanner = scan_scalar;
        break;
    }
}

int zone_scan_fast2_quicktest(void) {
    static struct testcases {
        const char *data;
        size_t expected;
    } tests[] = {
        {"abc \naaa", 4},
        {"abcd\t\naaa", 5},
        {"abcde\naaaa", 5},
        {"abcdef\r\naaa", 7},
        {"abc\\ def\naaa", 3},
        {"abc x def ) \naaa", 10},
        {"abc ( def ) \naaa", 4},
        {"abc    ; comment ( ) \n def ) \naaa", 7},
        {0,0}
    };
    
    int err = 0;
    
    for (int i=0; tests[i].data; i++) {
        char buf[1024];
        size_t in_len = strlen(tests[i].data);
        memset(buf, '\n', sizeof(buf));
        memcpy(buf, tests[i].data, in_len);
        
        size_t out = zone_scan_fast2(buf, 0, in_len);
        if (out != tests[i].expected) {
            fprintf(stderr, "[-] scan.fast2(): test %d failed: \"%s\"\n", i, tests[i].data);
            err++;
        }
    }
    
    return err;
}

