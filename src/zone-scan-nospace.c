// zone-scan-nospace.c
//
// =============================== FULL SPEC ==================================
// Goal:
//   Implement a fast zonefile scanner function `zone_scan_nospace()` that scans
//   forward from an initial index until it finds a delimiter byte.
//
// Function signature:
//   size_t zone_scan_nospace(const char *data, size_t i, size_t maxlen);
//
// Return value:
//   Returns the index (relative to `data`) of the first delimiter found at or
//   after `i`. The delimiter byte itself is NOT consumed.
//
// Delimiters / trigger bytes for this scanner:
//   - space      0x20  (' ')
//   - tab        0x09  ('\t')
//   - newline    0x0A  ('\n')          [NOTE: no '\r' carriage return]
//   - open paren '('
//   - close paren ')'
//   - semicolon  ';'
//
// Input / safety contract from caller (critical rules):
//   - The input will always contain at least one terminating trigger byte ahead
//     (e.g., whitespace or newline).
//   - The input will be padded so the implementation may read at least 64 bytes
//     beyond the logical end of input without fault.
//   - Therefore, no explicit bounds checks are required, and `maxlen` is a
//     vestigial parameter that is always ignored (but must remain in the API).
//
// Multi-architecture requirement:
//   - Provide multiple internal implementations for different SIMD
//     architectures, plus scalar/SWAR fallbacks.
//   - Internal functions must be `static` and have simple names:
//       scan_scalar, scan_swar, scan_sse2, scan_sse42, scan_avx2,
//       scan_avx512, scan_neon, scan_sve2, scan_riscvv.
//   - Scalar and SWAR variants are always compiled (no #ifdef).
//   - SIMD variants must be wrapped in conditional compilation blocks:
//       #ifdef SIMD_SSE2, SIMD_SSE42, SIMD_AVX2, SIMD_AVX512,
//       SIMD_NEON, SIMD_SVE2, SIMD_RISCVV.
//   - The SSE4.2 variant MUST use SSE4.2 text/string processing instructions
//     (PCMPISTRI/PCMPISTRM; e.g., via _mm_cmpestri).
//
// Portability requirement:
//   - Must work on Windows/MSVC as well as clang/gcc.
//   - Provide ctz32/ctz64 helpers that work under MSVC (BitScanForward) and
//     under gcc/clang (__builtin_ctz/__builtin_ctzll).
//
// Dispatch requirement:
//   - You will write your own runtime dispatch elsewhere.
//   - This file may provide a simple baseline default in zone_scan_nospace()
//     (e.g., calling scan_swar), but must not implement runtime CPU detection.
//
// ============================================================================

#include "zone-scan.h"
#include "util-ctz.h"
#include <string.h> // memcpy

/* -------------------------------- scalar ---------------------------------- */

static inline size_t
scan_scalar(const char *data, size_t i, size_t maxlen_ignored)
{
    (void)maxlen_ignored;
    for (;;) {
        unsigned char c = (unsigned char)data[i];
        if (c == 0x20u || c == 0x09u || c == 0x0Au ||
            c == (unsigned char)'(' || c == (unsigned char)')' || c == (unsigned char)';')
            return i;
        i++;
    }
}

/* --------------------------------- SWAR ----------------------------------- */

static inline uint64_t repeat_u8(uint8_t c) { return (uint64_t)c * 0x0101010101010101ULL; }

static inline uint64_t has_eq_u8(uint64_t x, uint8_t c)
{
    uint64_t y = x ^ repeat_u8(c);
    return (y - 0x0101010101010101ULL) & ~y & 0x8080808080808080ULL;
}

static inline size_t
scan_swar(const char *data, size_t i, size_t maxlen_ignored)
{
    (void)maxlen_ignored;
    for (;;) {
        uint64_t w;
        memcpy(&w, data + i, 8);

        uint64_t m =
            has_eq_u8(w, 0x20u) | // space
            has_eq_u8(w, 0x09u) | // tab
            has_eq_u8(w, 0x0Au) | // LF
            has_eq_u8(w, (uint8_t)'(') |
            has_eq_u8(w, (uint8_t)')') |
            has_eq_u8(w, (uint8_t)';');

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
scan_sse2(const char *data, size_t i, size_t maxlen_ignored)
{
    (void)maxlen_ignored;

    const __m128i sp = _mm_set1_epi8((char)0x20);
    const __m128i tb = _mm_set1_epi8((char)0x09);
    const __m128i nl = _mm_set1_epi8((char)0x0A);
    const __m128i lp = _mm_set1_epi8('(');
    const __m128i rp = _mm_set1_epi8(')');
    const __m128i sc = _mm_set1_epi8(';');

    for (;;) {
        __m128i v = _mm_loadu_si128((const __m128i *)(const void *)(data + i));

        __m128i m =
            _mm_or_si128(
                _mm_or_si128(_mm_cmpeq_epi8(v, sp), _mm_cmpeq_epi8(v, tb)),
                _mm_or_si128(
                    _mm_cmpeq_epi8(v, nl),
                    _mm_or_si128(_mm_or_si128(_mm_cmpeq_epi8(v, lp), _mm_cmpeq_epi8(v, rp)),
                                 _mm_cmpeq_epi8(v, sc))));

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
scan_sse42(const char *data, size_t i, size_t maxlen_ignored)
{
    (void)maxlen_ignored;

    // SSE4.2 text/string instruction (PCMPISTRI via _mm_cmpestri):
    const __m128i needle = _mm_setr_epi8((char)0x20, (char)0x09, (char)0x0A,
                                         '(', ')', ';',
                                         0,0,0,0,0,0,0,0,0,0);
    const int needle_len = 6;
    const int mode = _SIDD_UBYTE_OPS | _SIDD_CMP_EQUAL_ANY | _SIDD_LEAST_SIGNIFICANT;

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
scan_avx2(const char *data, size_t i, size_t maxlen_ignored)
{
    (void)maxlen_ignored;

    const __m256i sp = _mm256_set1_epi8((char)0x20);
    const __m256i tb = _mm256_set1_epi8((char)0x09);
    const __m256i nl = _mm256_set1_epi8((char)0x0A);
    const __m256i lp = _mm256_set1_epi8('(');
    const __m256i rp = _mm256_set1_epi8(')');
    const __m256i sc = _mm256_set1_epi8(';');

    for (;;) {
        __m256i v = _mm256_loadu_si256((const __m256i *)(const void *)(data + i));

        __m256i m =
            _mm256_or_si256(
                _mm256_or_si256(_mm256_cmpeq_epi8(v, sp), _mm256_cmpeq_epi8(v, tb)),
                _mm256_or_si256(
                    _mm256_cmpeq_epi8(v, nl),
                    _mm256_or_si256(_mm256_or_si256(_mm256_cmpeq_epi8(v, lp), _mm256_cmpeq_epi8(v, rp)),
                                    _mm256_cmpeq_epi8(v, sc))));

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
scan_avx512(const char *data, size_t i, size_t maxlen_ignored)
{
    (void)maxlen_ignored;

    const __m512i sp = _mm512_set1_epi8((char)0x20);
    const __m512i tb = _mm512_set1_epi8((char)0x09);
    const __m512i nl = _mm512_set1_epi8((char)0x0A);
    const __m512i lp = _mm512_set1_epi8('(');
    const __m512i rp = _mm512_set1_epi8(')');
    const __m512i sc = _mm512_set1_epi8(';');

    for (;;) {
        __m512i v = _mm512_loadu_si512((const void *)(data + i));

        __mmask64 m =
            _mm512_cmpeq_epi8_mask(v, sp) |
            _mm512_cmpeq_epi8_mask(v, tb) |
            _mm512_cmpeq_epi8_mask(v, nl) |
            _mm512_cmpeq_epi8_mask(v, lp) |
            _mm512_cmpeq_epi8_mask(v, rp) |
            _mm512_cmpeq_epi8_mask(v, sc);

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
scan_neon(const char *data, size_t i, size_t maxlen_ignored)
{
    (void)maxlen_ignored;

    const uint8x16_t sp = vdupq_n_u8(0x20);
    const uint8x16_t tb = vdupq_n_u8(0x09);
    const uint8x16_t nl = vdupq_n_u8(0x0A);
    const uint8x16_t lp = vdupq_n_u8((uint8_t)'(');
    const uint8x16_t rp = vdupq_n_u8((uint8_t)')');
    const uint8x16_t sc = vdupq_n_u8((uint8_t)';');

    for (;;) {
        uint8x16_t v = vld1q_u8((const uint8_t *)(const void *)(data + i));

        uint8x16_t m =
            vorrq_u8(
                vorrq_u8(vceqq_u8(v, sp), vceqq_u8(v, tb)),
                vorrq_u8(
                    vceqq_u8(v, nl),
                    vorrq_u8(vorrq_u8(vceqq_u8(v, lp), vceqq_u8(v, rp)),
                             vceqq_u8(v, sc))));

        if (neon_any(m)) {
            for (unsigned j = 0; j < 16; j++) {
                unsigned char c = (unsigned char)data[i + j];
                if (c == 0x20u || c == 0x09u || c == 0x0Au ||
                    c == (unsigned char)'(' || c == (unsigned char)')' || c == (unsigned char)';')
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
scan_sve2(const char *data, size_t i, size_t maxlen_ignored)
{
    (void)maxlen_ignored;

    const uint8_t c_sp = 0x20, c_tb = 0x09, c_nl = 0x0A;
    const uint8_t c_lp = (uint8_t)'(', c_rp = (uint8_t)')', c_sc = (uint8_t)';';

    for (;;) {
        svbool_t pg = svptrue_b8();
        svuint8_t v = svld1_u8(pg, (const uint8_t *)(const void *)(data + i));

        svbool_t m = svcmpeq_n_u8(pg, v, c_sp);
        m = svorr_b_z(pg, m, svcmpeq_n_u8(pg, v, c_tb));
        m = svorr_b_z(pg, m, svcmpeq_n_u8(pg, v, c_nl));
        m = svorr_b_z(pg, m, svcmpeq_n_u8(pg, v, c_lp));
        m = svorr_b_z(pg, m, svcmpeq_n_u8(pg, v, c_rp));
        m = svorr_b_z(pg, m, svcmpeq_n_u8(pg, v, c_sc));

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
scan_riscvv(const char *data, size_t i, size_t maxlen_ignored)
{
    (void)maxlen_ignored;

    for (;;) {
        size_t vl = vsetvlmax_e8m1();
        vuint8m1_t v = vle8_v_u8m1((const uint8_t *)(const void *)(data + i), vl);

        vbool8_t m = vmseq_vx_u8m1_b8(v, (uint8_t)0x20, vl);
        m = vmor_mm(m, vmseq_vx_u8m1_b8(v, (uint8_t)0x09, vl), vl);
        m = vmor_mm(m, vmseq_vx_u8m1_b8(v, (uint8_t)0x0A, vl), vl);
        m = vmor_mm(m, vmseq_vx_u8m1_b8(v, (uint8_t)'(',   vl), vl);
        m = vmor_mm(m, vmseq_vx_u8m1_b8(v, (uint8_t)')',   vl), vl);
        m = vmor_mm(m, vmseq_vx_u8m1_b8(v, (uint8_t)';',   vl), vl);

        long idx = vfirst_m_b8(m, vl);
        if (idx >= 0)
            return i + (size_t)idx;

        i += vl;
    }
}
#endif /* SIMD_RISCVV */


/* --------------------------- public entry point ---------------------------- */

size_t (*zone_scan_nospace)(const char *data, size_t offset, size_t len) = scan_scalar;
#define scanner zone_scan_nospace

void zone_scan_nospace_init(simd_backend_t backend) {
    switch (backend) {
    case SIMD_AUTO:zone_scan_nospace_init(simd_get_best());break;
    case SIMD_SCALAR: scanner = scan_scalar; break;
    case SIMD_SWAR: scanner = scan_swar; break;
#if defined(SIMD_SSE2)
    case SIMD_SSE2: scanner = scan_sse2; break;
#endif
#if defined(SIMD_SSE42)
    case SIMD_SSE42: scanner = scan_sse42; break;
#endif
#if defined(SIMD_AVX2)
    case SIMD_AVX2: scanner = scan_avx2; break;
#endif
#if defined(SIMD_AVX512)
    case SIMD_AVX512: scanner = scan_avx512; break;
#endif
#if defined(SIMD_NEON)
    case SIMD_NEON: scanner = scan_neon; break;
#endif
#if defined(SIMD_SVE2)
    case SIMD_SVE2: scanner = scan_sve2; break;
#endif
#if defined(SIMD_RISCVV)
    case SIMD_RISCVV: scanner = scan_riscvv; break;
#endif
    default: scanner = scan_scalar; break;
    }
}

int zone_scan_nospace_quicktest(void) {
    static struct testcases {
        const char *data;
        size_t expected;
    } tests[] = {
        {"abc xyz\n", 3},
        {"abc\txyz\n", 3},
        {"abc(xyz\n", 3},
        {"abc)xyz\n", 3},
        {"abc;xyz\n", 3},
        {"abc\r\nxyz\n", 4},
        {"abc\nxyz\n", 3},
        {"abcd\t\n", 4},
        {"abcde\n", 5},
        {"abcdef\r\n", 7},
        {0,0}
    };
    
    int err = 0;
    
    for (int i=0; tests[i].data; i++) {
        char buf[1024];
        size_t in_len = strlen(tests[i].data);
        memset(buf, '\n', sizeof(buf));
        memcpy(buf, tests[i].data, in_len);
        
        size_t out = zone_scan_nospace(buf, 0, in_len);
        if (out != tests[i].expected) {
            fprintf(stderr, "[-] scan.nospace(): test %d failed: \"%s\"\n", i, tests[i].data);
            err++;
        }
    }
    
    return err;
}



