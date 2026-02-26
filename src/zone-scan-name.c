// zone-scan-name.c
//
// Contract (per caller):
// - There is always at least one trigger byte ahead (at minimum '\n').
// - The buffer is padded so we may read at least 64 bytes past (data+len)
//   without fault.
// Therefore: no length checks needed; we can scan until the first trigger.
//
// Trigger bytes for "end of DNS name":
//   ' ' (0x20), '\t' (0x09), '(' , ';' , '\n' (0x0a), '\\' (0x5c)
// Return: number of bytes consumed before the first trigger.

#include "zone-scan.h"
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>

/* -------------------------------- scalar ---------------------------------- */
static inline size_t
scan_name_scalar(const char *data, size_t i, size_t len_ignored)
{
    (void)len_ignored;

    for (;;) {
        unsigned char c = (unsigned char)data[i];
        if (c == 0x20u || c == 0x09u || c == (unsigned char)'(' ||
            c == (unsigned char)';' || c == 0x0Au || c == (unsigned char)'\\')
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
scan_name_swar(const char *data, size_t i, size_t len_ignored)
{
    (void)len_ignored;

    for (;;) {
        uint64_t w;
        __builtin_memcpy(&w, data + i, 8);

        uint64_t m =
            zone_has_eq_u8(w, 0x20u) |                // space
            zone_has_eq_u8(w, 0x09u) |                // tab
            zone_has_eq_u8(w, (uint8_t)'(') |
            zone_has_eq_u8(w, (uint8_t)';') |
            zone_has_eq_u8(w, 0x0Au) |                // newline
            zone_has_eq_u8(w, (uint8_t)'\\');

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
scan_name_sse2(const char *data, size_t i, size_t len_ignored)
{
    (void)len_ignored;

    const __m128i sp = _mm_set1_epi8((char)0x20);
    const __m128i tb = _mm_set1_epi8((char)0x09);
    const __m128i op = _mm_set1_epi8('(');
    const __m128i sc = _mm_set1_epi8(';');
    const __m128i nl = _mm_set1_epi8((char)0x0A);
    const __m128i bs = _mm_set1_epi8('\\');

    for (;;) {
        __m128i v = _mm_loadu_si128((const __m128i *)(const void *)(data + i));

        __m128i m = _mm_or_si128(
                        _mm_or_si128(_mm_cmpeq_epi8(v, sp), _mm_cmpeq_epi8(v, tb)),
                        _mm_or_si128(_mm_or_si128(_mm_cmpeq_epi8(v, op), _mm_cmpeq_epi8(v, sc)),
                                     _mm_or_si128(_mm_cmpeq_epi8(v, nl), _mm_cmpeq_epi8(v, bs))));

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
scan_name_sse42(const char *data, size_t i, size_t len_ignored)
{
    (void)len_ignored;

    // SSE4.2 text/string instruction (PCMPISTRI/PCMPIESTRI via _mm_cmpestri):
    // Find first byte in haystack that equals any byte in the needle set.
    const __m128i needle = _mm_setr_epi8((char)0x20, (char)0x09, '(', ';',
                                         (char)0x0A, '\\',
                                         0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    const int needle_len = 6;
#define mode  _SIDD_UBYTE_OPS | _SIDD_CMP_EQUAL_ANY | _SIDD_LEAST_SIGNIFICANT

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
scan_name_avx2(const char *data, size_t i, size_t len_ignored)
{
    (void)len_ignored;

    const __m256i sp = _mm256_set1_epi8((char)0x20);
    const __m256i tb = _mm256_set1_epi8((char)0x09);
    const __m256i op = _mm256_set1_epi8('(');
    const __m256i sc = _mm256_set1_epi8(';');
    const __m256i nl = _mm256_set1_epi8((char)0x0A);
    const __m256i bs = _mm256_set1_epi8('\\');

    for (;;) {
        __m256i v = _mm256_loadu_si256((const __m256i *)(const void *)(data + i));

        __m256i m =
            _mm256_or_si256(
                _mm256_or_si256(_mm256_cmpeq_epi8(v, sp), _mm256_cmpeq_epi8(v, tb)),
                _mm256_or_si256(
                    _mm256_or_si256(_mm256_cmpeq_epi8(v, op), _mm256_cmpeq_epi8(v, sc)),
                    _mm256_or_si256(_mm256_cmpeq_epi8(v, nl), _mm256_cmpeq_epi8(v, bs))));

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
scan_name_avx512(const char *data, size_t i, size_t len_ignored)
{
    (void)len_ignored;

    const __m512i sp = _mm512_set1_epi8((char)0x20);
    const __m512i tb = _mm512_set1_epi8((char)0x09);
    const __m512i op = _mm512_set1_epi8('(');
    const __m512i sc = _mm512_set1_epi8(';');
    const __m512i nl = _mm512_set1_epi8((char)0x0A);
    const __m512i bs = _mm512_set1_epi8('\\');

    for (;;) {
        __m512i v = _mm512_loadu_si512((const void *)(data + i));

        __mmask64 m =
            _mm512_cmpeq_epi8_mask(v, sp) |
            _mm512_cmpeq_epi8_mask(v, tb) |
            _mm512_cmpeq_epi8_mask(v, op) |
            _mm512_cmpeq_epi8_mask(v, sc) |
            _mm512_cmpeq_epi8_mask(v, nl) |
            _mm512_cmpeq_epi8_mask(v, bs);

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
scan_name_neon(const char *data, size_t i, size_t len_ignored)
{
    (void)len_ignored;

    const uint8x16_t sp = vdupq_n_u8(0x20);
    const uint8x16_t tb = vdupq_n_u8(0x09);
    const uint8x16_t op = vdupq_n_u8((uint8_t)'(');
    const uint8x16_t sc = vdupq_n_u8((uint8_t)';');
    const uint8x16_t nl = vdupq_n_u8(0x0A);
    const uint8x16_t bs = vdupq_n_u8((uint8_t)'\\');

    for (;;) {
        uint8x16_t v = vld1q_u8((const uint8_t *)(const void *)(data + i));

        uint8x16_t m =
            vorrq_u8(
                vorrq_u8(vceqq_u8(v, sp), vceqq_u8(v, tb)),
                vorrq_u8(
                    vorrq_u8(vceqq_u8(v, op), vceqq_u8(v, sc)),
                    vorrq_u8(vceqq_u8(v, nl), vceqq_u8(v, bs))));

        if (zone_neon_any_match(m)) {
            for (unsigned j = 0; j < 16; j++) {
                unsigned char c = (unsigned char)data[i + j];
                if (c == 0x20u || c == 0x09u || c == (unsigned char)'(' ||
                    c == (unsigned char)';' || c == 0x0Au || c == (unsigned char)'\\')
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
scan_name_sve2(const char *data, size_t i, size_t len_ignored)
{
    (void)len_ignored;

    const uint8_t c_sp = 0x20u;
    const uint8_t c_tb = 0x09u;
    const uint8_t c_op = (uint8_t)'(';
    const uint8_t c_sc = (uint8_t)';';
    const uint8_t c_nl = 0x0Au;
    const uint8_t c_bs = (uint8_t)'\\';

    for (;;) {
        svbool_t pg = svptrue_b8();
        svuint8_t v = svld1_u8(pg, (const uint8_t *)(const void *)(data + i));

        svbool_t m = svcmpeq_n_u8(pg, v, c_sp);
        m = svorr_b_z(pg, m, svcmpeq_n_u8(pg, v, c_tb));
        m = svorr_b_z(pg, m, svcmpeq_n_u8(pg, v, c_op));
        m = svorr_b_z(pg, m, svcmpeq_n_u8(pg, v, c_sc));
        m = svorr_b_z(pg, m, svcmpeq_n_u8(pg, v, c_nl));
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
scan_name_riscvv(const char *data, size_t i, size_t len_ignored)
{
    (void)len_ignored;

    for (;;) {
        size_t vl = vsetvlmax_e8m1();

        vuint8m1_t v = vle8_v_u8m1((const uint8_t *)(const void *)(data + i), vl);

        vbool8_t m = vmseq_vx_u8m1_b8(v, (uint8_t)0x20, vl);
        m = vmor_mm(m, vmseq_vx_u8m1_b8(v, (uint8_t)0x09, vl), vl);
        m = vmor_mm(m, vmseq_vx_u8m1_b8(v, (uint8_t)'(', vl), vl);
        m = vmor_mm(m, vmseq_vx_u8m1_b8(v, (uint8_t)';', vl), vl);
        m = vmor_mm(m, vmseq_vx_u8m1_b8(v, (uint8_t)0x0A, vl), vl);
        m = vmor_mm(m, vmseq_vx_u8m1_b8(v, (uint8_t)'\\', vl), vl);

        long idx = vfirst_m_b8(m, vl);
        if (idx >= 0)
            return i + (size_t)idx;

        i += vl;
    }
}
#endif /* SIMD_RISCVV */

static size_t (*scanner)(const char *data, size_t offset, size_t len) = scan_name_scalar;

size_t zone_scan_name(const char *data, size_t offset, size_t len) {
    
    for (;;) {
        
        /* fast SIMD scan */
        offset = scanner(data, offset, len);
        
        char c = data[offset];
        
        /* Names are expected to end in a space
         * TODO: speed up this test with a lookup */
        if (c == ' ' || c == '\t' || c == '(' || c == ';')
            return offset; /* SUCCESS! */
        
        /* A newline is actually an error, but let's pretend it
         * isn't at this point (catching it in the next step).
         * Maybe I should treat it as an error and not search
         * for a newline '\n' at all. */
        if (c == '\n') {
            if (len > 0 && data[offset - 1] == '\r')
                offset--;
            return offset;
        }
        
        if (c == '\\') {
            offset = zone_scan_escape(data, offset, len);
            continue;
        }
        
        assert(!"not possible");
        return len + 1;
    }
    return len + 1; /* error */
}



void zone_scan_name_init(simd_backend_t backend) {
    switch (backend) {
    case SIMD_AUTO: zone_scan_name_init(simd_get_best()); break;
    case SIMD_SCALAR: scanner = scan_name_scalar; break;
    case SIMD_SWAR: scanner = scan_name_swar; break;
#if defined(SIMD_SSE2)
    case SIMD_SSE2: scanner = scan_name_sse2; break;
#endif
#if defined(SIMD_SSE42)
    case SIMD_SSE42: scanner = scan_name_sse42; break;
#endif
#if defined(SIMD_AVX2)
    case SIMD_AVX2: scanner = scan_name_avx2; break;
#endif
#if defined(SIMD_AVX512)
    case SIMD_AVX512: scanner = scan_name_avx512; break;
#endif
#if defined(SIMD_NEON)
    case SIMD_NEON: scanner = scan_name_neon; break;
#endif
#if defined(SIMD_SVE2)
    case SIMD_SVE2: scanner = scan_name_sve2; break;
#endif
#if defined(SIMD_RISCVV)
    case SIMD_RISCVV: scanner = scan_name_riscvv; break;
#endif
    default: scanner = scan_name_scalar; break;
    }
}

static struct testcases {
    const char *input;
    unsigned out_len;
} tests[] = {
    
    // Basic valid names
    { "example.com", 11 },
    { "a.b", 3 },
    { "www", 3 },
    
    // Names ending with space (space ends the name in zone files)
    { "test.com ", 8 },
    { "test.com\t", 8 },
    { "test.com(", 8 },
    { "test.com;", 8 },
    { "test.com\n", 8 },
    { "test.com\r\n", 8 },
    { "a b c ", 1 },
    
    // Names ending with semicolon
    { "test.com;", 8 },
    { "domain; comment", 6 },
    
    // Escaped special characters within names
    { "test\\.com", 9 },  // Escaped dot
    { "space\\ test", 11 }, // Escaped space
    { "tab\\\ttest", 9 }, // Escaped space
    { "semi\\;colon", 11 }, // Escaped semicolon
    { "backslash\\", 11 },  // Escaped backslash
    { "open\\(paren", 11 }, // Escaped open paren
    { "close\\)paren", 12 }, // Escaped close paren
    
    // Multiple escapes
    { "multi\\ esc\\;ape", 15 },
    { "\\e\\s\\c\\a\\p\\e\\d", 14 },
    
    // Edge cases
    { "", 0 },                    // Empty name
    { " ", 0 },                   // Single space (ends immediately after label)
    { "\\ ", 2 },                 // Escaped space as single character label
    { "a\\ b\\ c", 7 },           // Multi-char label with embedded escaped spaces
    { "end\\;with\\;", 11 },      // Ends with escaped semicolon
    
    // Longer names with terminators
    { "very.long.example.com. ", 22 },
    { "domain;next", 6 },
    
    // Maximum label length with escape
    { "12345678901234567890123456789012345678901234567890123456789012345678901234567890\\ ", 82 },
    
    {0,0}
};

int zone_scan_name_quicktest(void) {
    int err = 0;
    char buf[1024];
    memset(buf, '\n', sizeof(buf));
    
    for (int i=0; tests[i].input; i++) {
        char *data;
        size_t max = strlen(tests[i].input);

        /* prep for SIMD */
        data = malloc(max + 1024);
        memcpy(data, tests[i].input, max);
        memcpy(data + max, "\n \n", 4);
        
        size_t out_len = zone_scan_name(data, 0, max);
        if (out_len != tests[i].out_len) {
            fprintf(stderr, "[-] scan.name(): test %d failed, len=%u, \"%s\"\n", i, (unsigned)out_len, tests[i].input);
            err++;
        }
        free(data);
    }
    
    return err;
}
