// zone-scan-space.c
//
// Contract (per caller):
// - There is always at least one trigger byte ahead.
// - The buffer is padded so we may read at least 64 bytes past the logical end.
// Therefore: no bounds checks needed; we scan until a trigger.
//
// Trigger bytes (whitespace):
//   ' ' (0x20), '\t' (0x09), '\r' (0x0D), '\n' (0x0A)
//
// API shape (matching your other scanners):
//   size_t zone_scan_space(const char *data, size_t i, size_t len_ignored);
//
// Return: index of first trigger relative to data.


// zone-scan-space.c
//
// =============================== FULL SPEC ==================================
// Goal:
//   Implement a fast zonefile whitespace skipper `zone_scan_space()` that scans
//   forward over "ignorable" characters and returns the index of the next
//   significant byte.
//
// Base scanning rule:
//   - First, use a fast scanner ("scanner") that scans forward until it reaches
//     any character OTHER than:
//        * space 0x20 (' ')
//        * tab   0x09 ('\t')
//     i.e., it finds the first non-(space/tab) byte.
//
// Then interpret the stopping byte and apply zonefile semantics:
//   - '('  : increase *depth, consume it, then continue scanning
//   - ')'  : decrease *depth (not below 0), consume it, then continue scanning
//   - ';'  : treat as comment start:
//              * call existing `zone_scan_eol()` to find the '\n' ending comment
//              * if *depth != 0: consume the newline (and continue scanning)
//              * if *depth == 0: stop and return the index of the newline
//   - '\n' or '\r\n':
//              * if *depth != 0: consume the newline (CRLF counts as one newline)
//                and continue scanning
//              * if *depth == 0: stop and return the index of '\n' or '\r'
//
// Termination:
//   - If the stopping byte is anything else, stop and return its index.
//
// API:
//   - Internal fast scanner function pointer "scanner" is created in this file
//     (compile-time chosen baseline; NO runtime CPU detection here).
//   - Exported function:
//        size_t zone_scan_space(const char *data, size_t i, size_t maxlen, size_t *depth);
//     where `depth` is an in/out parameter.
//
// Return value:
//   - Returns the index of the first significant byte (or newline boundary when
//     *depth==0), relative to `data`. The byte at that index is NOT consumed.
//
// Caller-provided safety contract (critical rules):
//   - Input always has a terminating condition ahead (e.g., newline / delimiter).
//   - Input is padded so implementations may read at least 64 bytes beyond the
//     logical end safely.
//   - Therefore NO bounds checks are required; `maxlen` is vestigial and ignored
//     (but must remain in the API).
//
// Multi-architecture requirement for the internal fast scanner:
//   - Provide internal implementations for: scalar, swar, SSE2, SSE4.2, AVX2,
//     AVX-512, NEON, SVE2, RISCVV.
//   - Internal functions must be `static` and have simple names:
//       scan_scalar, scan_swar, scan_sse2, scan_sse42, scan_avx2,
//       scan_avx512, scan_neon, scan_sve2, scan_riscvv.
//   - Scalar and SWAR are always compiled (no #ifdef).
//   - SIMD variants are wrapped in #ifdef SIMD_* blocks.
//   - SSE4.2 variant MUST use SSE4.2 text/string processing instructions
//     (PCMPISTRI/PCMPISTRM; e.g., _mm_cmpestri).
//
// Portability requirement:
//   - Must compile under Windows/MSVC and clang/gcc.
//   - Provide ctz32/ctz64 helpers using BitScanForward / __builtin_ctz.
//
// External dependency:
//   - `zone_scan_eol(const char *data, size_t i, size_t maxlen)` exists elsewhere.
//     It returns the index of the '\n' ending the current line, starting from i.
// ============================================================================
#include "zone-scan.h"
#include "util-ctz.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h> // memcpy

//extern size_t zone_scan_eol(const char *data, size_t i, size_t maxlen);

/* --------------------------- byte-equality (SWAR) -------------------------- */

static inline uint64_t repeat_u8(uint8_t c) { return (uint64_t)c * 0x0101010101010101ULL; }

static inline uint64_t has_eq_u8(uint64_t x, uint8_t c)
{
    uint64_t y = x ^ repeat_u8(c);
    return (y - 0x0101010101010101ULL) & ~y & 0x8080808080808080ULL;
}

/* -------------------------------- scalar ---------------------------------- */
/* Returns index of first byte != ' ' and != '\t'. */
static size_t
scan_scalar(const char *data, size_t i, size_t maxlen_ignored)
{
    (void)maxlen_ignored;
    for (;;) {
        unsigned char c = (unsigned char)data[i];
        if (!(c == 0x20u || c == 0x09u))
            return i;
        i++;
    }
}

/* --------------------------------- SWAR ----------------------------------- */
/* Returns index of first byte != ' ' and != '\t'. */
static size_t
scan_swar(const char *data, size_t i, size_t maxlen_ignored)
{
    (void)maxlen_ignored;

    for (;;) {
        uint64_t w;
        memcpy(&w, data + i, 8);

        // Each matching byte sets its high bit (0x80 in that byte lane).
        uint64_t m_space = has_eq_u8(w, 0x20u);
        uint64_t m_tab   = has_eq_u8(w, 0x09u);
        uint64_t m_ok    = m_space | m_tab;

        // Want first NOT ok => high-bit set in those lanes.
        uint64_t m_bad = (~m_ok) & 0x8080808080808080ULL;

        if (m_bad) {
            unsigned bit = ctz64(m_bad);
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

    for (;;) {
        __m128i v = _mm_loadu_si128((const __m128i *)(const void *)(data + i));
        __m128i eq = _mm_or_si128(_mm_cmpeq_epi8(v, sp), _mm_cmpeq_epi8(v, tb));
        unsigned ok = (unsigned)_mm_movemask_epi8(eq);
        unsigned bad = (~ok) & 0xFFFFu;
        if (bad) {
            unsigned idx = ctz32(bad);
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

    // Find first byte NOT equal to any of {' ', '\t'} using SSE4.2 string compare.
    const __m128i needle = _mm_setr_epi8((char)0x20, (char)0x09,
                                         0,0,0,0,0,0,0,0,0,0,0,0,0,0);
    const int needle_len = 2;
    const int mode =
        _SIDD_UBYTE_OPS |
        _SIDD_CMP_EQUAL_ANY |
        _SIDD_NEGATIVE_POLARITY |     // invert match: find first NOT in needle
        _SIDD_LEAST_SIGNIFICANT;

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

    for (;;) {
        __m256i v = _mm256_loadu_si256((const __m256i *)(const void *)(data + i));
        __m256i eq = _mm256_or_si256(_mm256_cmpeq_epi8(v, sp), _mm256_cmpeq_epi8(v, tb));
        unsigned ok = (unsigned)_mm256_movemask_epi8(eq);
        if (ok != 0xFFFFFFFFu) {
            unsigned bad = ~ok;
            unsigned idx = ctz32(bad);
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

    for (;;) {
        __m512i v = _mm512_loadu_si512((const void *)(data + i));
        __mmask64 ok = _mm512_cmpeq_epi8_mask(v, sp) | _mm512_cmpeq_epi8_mask(v, tb);
        if (ok != ~(__mmask64)0) {
            uint64_t bad = (uint64_t)(~ok);
            unsigned idx = ctz64(bad);
            return i + (size_t)idx;
        }
        i += 64;
    }
}
#endif /* SIMD_AVX512 */

/* --------------------------------- NEON ----------------------------------- */
#ifdef SIMD_NEON
  #include <arm_neon.h>
static inline int neon_any_u8(uint8x16_t m)
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

    for (;;) {
        uint8x16_t v = vld1q_u8((const uint8_t *)(const void *)(data + i));
        uint8x16_t eq = vorrq_u8(vceqq_u8(v, sp), vceqq_u8(v, tb));
        uint8x16_t bad = vmvnq_u8(eq);
        if (neon_any_u8(bad)) {
            for (unsigned j = 0; j < 16; j++) {
                unsigned char c = (unsigned char)data[i + j];
                if (!(c == 0x20u || c == 0x09u))
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

    for (;;) {
        svbool_t pg = svptrue_b8();
        svuint8_t v = svld1_u8(pg, (const uint8_t *)(const void *)(data + i));
        svbool_t ok = svcmpeq_n_u8(pg, v, 0x20);
        ok = svorr_b_z(pg, ok, svcmpeq_n_u8(pg, v, 0x09));

        svbool_t bad = svnot_b_z(pg, ok);
        if (svptest_any(pg, bad)) {
            svbool_t prefix = svbrkb_z(pg, bad);
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

        vbool8_t ok = vmseq_vx_u8m1_b8(v, (uint8_t)0x20, vl);
        ok = vmor_mm(ok, vmseq_vx_u8m1_b8(v, (uint8_t)0x09, vl), vl);

        vbool8_t bad = vmnot_m_b8(ok, vl);
        long idx = vfirst_m_b8(bad, vl);
        if (idx >= 0)
            return i + (size_t)idx;

        i += vl;
    }
}
#endif /* SIMD_RISCVV */

/* ------------------------------ scanner hook ------------------------------- */
/* No runtime dispatch here; choose a baseline fast implementation. */
static  size_t (*scanner)(const char *data, size_t i, size_t maxlen_ignored) = scan_swar;

/* ----------------------------- exported function --------------------------- */

size_t
zone_scan_space(const char *data, size_t i, size_t maxlen_ignored, unsigned *depth)
{
    (void)maxlen_ignored;

    for (;;) {
        size_t j = scanner(data, i, maxlen_ignored);
        unsigned char c = (unsigned char)data[j];

        // If it's not a special case, we're done: next significant byte.
        if (c != (unsigned char)'(' &&
            c != (unsigned char)')' &&
            c != (unsigned char)';' &&
            c != (unsigned char)'\n' &&
            c != (unsigned char)'\r') {
            return j;
        }

        if (c == (unsigned char)'(') {
            (*depth)++;
            i = j + 1;
            continue;
        }

        if (c == (unsigned char)')') {
            if (*depth) (*depth)--;
            i = j + 1;
            continue;
        }

        if (c == (unsigned char)';') {
            // Comment to end of line (zone_scan_eol returns index of '\n').
            size_t eol = zone_scan_eol(data, j, maxlen_ignored);
            if (*depth) {
                // Consume newline and continue scanning.
                i = eol + 1;
                continue;
            }
            // At depth 0, newline terminates the logical record.
            return eol;
        }

        // Newline handling: '\n' or '\r\n'
        if (c == (unsigned char)'\n') {
            if (*depth) {
                i = j + 1;
                continue;
            }
            return j;
        }

        // c == '\r'
        if ((unsigned char)data[j + 1] == (unsigned char)'\n') {
            if (*depth) {
                i = j + 2; // consume CRLF
                continue;
            }
            return j; // return CR at depth 0
        } else {
            if (*depth) {
                i = j + 1; // consume lone CR if present
                continue;
            }
            return j;
        }
    }
}


/* --------------------------- public entry point ---------------------------- */


void zone_scan_space_init(simd_backend_t backend) {
    switch (backend) {
    case SIMD_AUTO:zone_scan_space_init(simd_get_best());break;
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

int zone_scan_space_quicktest(void) {
    static struct testcases {
        const char *data;
        size_t expected;
    } tests[] = {
        {"   abc \n", 3},
        {" \t\t abcd\t\n", 4},
        {"  ", 2},
        {"a bcdef\r\n", 0},
        {0,0}
    };
    
    int err = 0;
    
    for (int i=0; tests[i].data; i++) {
        char buf[1024];
        size_t in_len = strlen(tests[i].data);
        unsigned depth = 0;
        memset(buf, '\n', sizeof(buf));
        memcpy(buf, tests[i].data, in_len);
        
        size_t out = zone_scan_space(buf, 0, in_len, &depth);
        if (out != tests[i].expected) {
            fprintf(stderr, "[-] scan.space(): test %d failed: \"%s\"\n", i, tests[i].data);
            err++;
        }
    }
    
    return err;
}



