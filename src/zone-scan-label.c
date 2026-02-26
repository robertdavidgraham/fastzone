// zone-scan-label.c
//
// Fast label scanner: advance within a DNS owner name until one of:
//   '.'   (end of label, not consumed by this function)
//   ' '   (0x20 end-of-name marker, guaranteed by caller; not consumed)
//   '\\'  (escape indicator; not consumed)
//
// Contract (per caller):
// - There is always a terminating space (0x20) somewhere ahead.
// - Buffer is padded so we may read at least 64 bytes past the logical end.
// Therefore: no bounds checks needed; we scan until a trigger.
//
// API:
//   size_t zone_scan_label(const char *data, size_t i, size_t maxlen_ignored);
// Returns: index of the first trigger relative to data.

#include "zone-scan.h"
#include "util-ctz.h"
#include <string.h> // memcpy
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>

/* -------------------------------- scalar ---------------------------------- */
static inline size_t
scan_scalar(const char *data, size_t i, size_t maxlen_ignored)
{
    (void)maxlen_ignored;
    for (;;) {
        unsigned char c = (unsigned char)data[i];
        if (c == (unsigned char)'.' || c == 0x20u || c == (unsigned char)'\\')
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
scan_swar(const char *data, size_t i, size_t maxlen_ignored)
{
    (void)maxlen_ignored;
    for (;;) {
        uint64_t w;
        memcpy(&w, data + i, 8);

        uint64_t m =
            has_eq_u8(w, (uint8_t)'.')  |
            has_eq_u8(w, (uint8_t)0x20) |
            has_eq_u8(w, (uint8_t)'\\');

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

    const __m128i c_dot = _mm_set1_epi8('.');
    const __m128i c_sp  = _mm_set1_epi8((char)0x20);
    const __m128i c_bs  = _mm_set1_epi8('\\');

    for (;;) {
        __m128i v = _mm_loadu_si128((const __m128i *)(const void *)(data + i));

        __m128i m = _mm_or_si128(
                        _mm_or_si128(_mm_cmpeq_epi8(v, c_dot), _mm_cmpeq_epi8(v, c_sp)),
                        _mm_cmpeq_epi8(v, c_bs));

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
    const __m128i needle = _mm_setr_epi8('.', (char)0x20, '\\',
                                         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    const int needle_len = 3;
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
scan_avx2(const char *data, size_t i, size_t maxlen_ignored)
{
    (void)maxlen_ignored;

    const __m256i c_dot = _mm256_set1_epi8('.');
    const __m256i c_sp  = _mm256_set1_epi8((char)0x20);
    const __m256i c_bs  = _mm256_set1_epi8('\\');

    for (;;) {
        __m256i v = _mm256_loadu_si256((const __m256i *)(const void *)(data + i));

        __m256i m = _mm256_or_si256(
                        _mm256_or_si256(_mm256_cmpeq_epi8(v, c_dot), _mm256_cmpeq_epi8(v, c_sp)),
                        _mm256_cmpeq_epi8(v, c_bs));

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

    const __m512i c_dot = _mm512_set1_epi8('.');
    const __m512i c_sp  = _mm512_set1_epi8((char)0x20);
    const __m512i c_bs  = _mm512_set1_epi8('\\');

    for (;;) {
        __m512i v = _mm512_loadu_si512((const void *)(data + i));

        __mmask64 m =
            _mm512_cmpeq_epi8_mask(v, c_dot) |
            _mm512_cmpeq_epi8_mask(v, c_sp)  |
            _mm512_cmpeq_epi8_mask(v, c_bs);

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

    const uint8x16_t c_dot = vdupq_n_u8((uint8_t)'.');
    const uint8x16_t c_sp  = vdupq_n_u8((uint8_t)0x20);
    const uint8x16_t c_bs  = vdupq_n_u8((uint8_t)'\\');

    for (;;) {
        uint8x16_t v = vld1q_u8((const uint8_t *)(const void *)(data + i));

        uint8x16_t m = vorrq_u8(
                           vorrq_u8(vceqq_u8(v, c_dot), vceqq_u8(v, c_sp)),
                           vceqq_u8(v, c_bs));

        if (neon_any(m)) {
            for (unsigned j = 0; j < 16; j++) {
                unsigned char c = (unsigned char)data[i + j];
                if (c == (unsigned char)'.' || c == 0x20u || c == (unsigned char)'\\')
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

    const uint8_t c_dot = (uint8_t)'.';
    const uint8_t c_sp  = (uint8_t)0x20;
    const uint8_t c_bs  = (uint8_t)'\\';

    for (;;) {
        svbool_t pg = svptrue_b8();
        svuint8_t v = svld1_u8(pg, (const uint8_t *)(const void *)(data + i));

        svbool_t m = svcmpeq_n_u8(pg, v, c_dot);
        m = svorr_b_z(pg, m, svcmpeq_n_u8(pg, v, c_sp));
        m = svorr_b_z(pg, m, svcmpeq_n_u8(pg, v, c_bs));

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

        vbool8_t m = vmseq_vx_u8m1_b8(v, (uint8_t)'.',  vl);
        m = vmor_mm(m, vmseq_vx_u8m1_b8(v, (uint8_t)0x20, vl), vl);
        m = vmor_mm(m, vmseq_vx_u8m1_b8(v, (uint8_t)'\\', vl), vl);

        long idx = vfirst_m_b8(m, vl);
        if (idx >= 0)
            return i + (size_t)idx;

        i += vl;
    }
}
#endif /* SIMD_RISCVV */

/* --------------------------- exported function ----------------------------- */

#define scanner zone_scan_label

size_t (*zone_scan_label)(const char *data, size_t i, size_t maxlen_ignored) = scan_scalar;

void zone_scan_label_init(simd_backend_t backend) {
    switch (backend) {
    case SIMD_AUTO:
        zone_scan_label_init(simd_get_best());
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

