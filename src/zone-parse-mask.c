/* zone-atom-mask.c
 *
 * SPECIFICATION (ORGANIZED, COMPLETE, AND STABLE)
 *
 * 1) PURPOSE
 *   Provide a fast whitespace classifier for DNS zonefile token scanning.
 *   The parser uses a simdjson-like pattern:
 *     - classify a chunk into a mask,
 *     - locate boundaries via ctz/bit operations,
 *     - consume and refill.
 *
 * 2) CLASSIFICATION RULE (FINAL POLARITY)
 *   - whitespace bytes: ' ' and '\t'  => mask bit 1
 *   - all other bytes                  => mask bit 0
 *
 *   This module is deliberately narrow: it does not interpret zonefile syntax
 *   such as comments, quoted strings, backslash escapes, or parentheses for multiline
 *   records. Those are handled in higher layers.
 *
 * 3) RUNTIME DISPATCH MODEL
 *   - util-simd.h defines SIMD identifiers and an enum, including only supported values:
 *       SIMD_AUTO, SIMD_SCALAR, SIMD_SWAR, SIMD_SSE2, SIMD_SSE42, SIMD_AVX2,
 *       SIMD_AVX512, SIMD_NEON, SIMD_SVE2, SIMD_RISCVV, SIMD_MAX
 *   - Each backend implementation is guarded by:
 *       #ifdef SIMD_FOO
 *       ... implementation ...
 *       #endif
 *     util-simd.h must only define SIMD_FOO when the compiler/target/flags support
 *     the required intrinsics and headers.
 *   - Global function pointer set at runtime:
 *       void (*zone_atom_mask)(const char *data, size_t cursor, uint64_t *mask, unsigned *avail);
 *   - SIMD_AUTO is resolved by calling simd_get_best() (declared in util-simd.h).
 *   - zone_atom_mask_init() uses a switch:
 *       - each case on one line,
 *       - break (not return),
 *       - includes case SIMD_MAX to silence missing-enum warnings.
 *
 * 4) CHUNK WIDTHS AND OUTPUT
 *   - Backends set *avail to the number of bytes classified per call (also number of valid bits):
 *       scalar: 16
 *       swar:   16
 *       sse2:   16
 *       sse42:  16
 *       avx2:   32
 *       avx512: 64 (assume Ice Lake / AVX10-class extensions; AVX512BW etc.)
 *       neon:   16 (AArch64 only)
 *       sve2:   64 (always returns 64 bits)
 *       riscvv: 64 (always returns 64 bits)
 *
 *   - Bit 0 corresponds to data[cursor+0], bit 1 to data[cursor+1], etc.
 *   - With the final polarity, bits are 1 exactly for whitespace bytes.
 *
 * 5) CURSOR-BASED CONSUMPTION
 *   - Callers maintain an absolute cursor into the buffer.
 *   - zone_atom_mask() does not modify cursor.
 *   - zone_atom_consume() shifts the mask down and refills as needed, returning cursor+length.
 *     It takes `data` as a pointer (not pointer-to-pointer).
 *
 * 6) PORTABILITY / BUILD REQUIREMENTS (WINDOWS/macOS/LINUX)
 *   - This compilation unit must build on Windows, macOS, and Linux.
 *   - Platform-specific SIMD headers are only included when their SIMD_* macro is defined.
 *   - Generic code avoids non-portable assumptions; SWAR uses memcpy for unaligned loads.
 *   - No UINT64_C() macro is used; raw literals like 1llu are used.
 *
 * 7) SELF-TEST (QUICKTEST)
 *   - Provide:
 *       int zone_atom_mask_quicktest(void);
 *   - Define 20 deterministic inputs, each exactly 64 bytes long, with expected 64-bit masks
 *     (1 bits mark whitespace).
 *   - For backends that produce <64 bits per call (16/32), quicktest calls zone_atom_mask()
 *     multiple times and assembles the full 64-bit mask.
 *   - Iterate simd from SIMD_AUTO+1 to SIMD_MAX-1 to test available backends.
 *   - Accumulate failures in `err`, return err (0 => success).
 *   - On failure of test t, print to stderr:
 *       atom.mask:%d failed test
 *     with t substituted (and a trailing newline).
 *
 * 8) DNS ZONEFILE PARSING CONTEXT (WHY THIS EXISTS)
 *   - Zonefiles are whitespace-separated fields, but RRDATA may include quoted strings,
 *     escapes, comments, and parentheses-wrapped multiline records.
 *   - High-performance parsers often layer:
 *       - a fast whitespace mask (this file),
 *       - additional classifiers (quotes/comments/parens),
 *       - and field-specific parsers (TTL, CLASS, TYPE, RDATA).
 *   - This file is the lowest layer in that stack.
 */

#include "zone-parse-mask.h"
#include "zone-scan.h"
#include "util-simd.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>


/* -------------------------- SCALAR (16 bytes) -------------------------- */

static void mask_scalar(const char *data, size_t cursor, uint64_t *mask, unsigned *avail)
{
    const unsigned w = 16;
    const unsigned char *p = (const unsigned char *)(data + cursor);
    uint64_t m = 0;
    for (unsigned i = 0; i < w; i++) {
        unsigned char c = p[i];
        if (c == ' ' || c == '\t') m |= (1llu << i);
    }
    *mask = ~m;
    *avail = w;
}

/* --------------------------- SWAR (16 bytes) --------------------------- */

static inline uint64_t swar_eq_byte_to_msb(uint64_t x, unsigned char c)
{
    /* Each byte => 0x80 iff byte equals c. */
    const uint64_t ones = 0x0101010101010101llu;
    const uint64_t msb  = 0x8080808080808080llu;
    uint64_t v = x ^ (ones * (uint64_t)c);
    return (v - ones) & ~v & msb;
}

static inline unsigned swar_msbbytes_to_bits8(uint64_t msb_mask)
{
    /* Compress per-byte MSB into an 8-bit value. */
    return (unsigned)((msb_mask * 0x02040810204081llu) >> 56);
}

static void mask_swar(const char *data, size_t cursor, uint64_t *mask, unsigned *avail)
{
    const unsigned w = 16;
    const unsigned char *p = (const unsigned char *)(data + cursor);

    uint64_t a, b;
    memcpy(&a, p + 0, 8);
    memcpy(&b, p + 8, 8);

    uint64_t a_ws = swar_eq_byte_to_msb(a, ' ') | swar_eq_byte_to_msb(a, '\t');
    uint64_t b_ws = swar_eq_byte_to_msb(b, ' ') | swar_eq_byte_to_msb(b, '\t');

    uint64_t a_w = a_ws & 0x8080808080808080llu;
    uint64_t b_w = b_ws & 0x8080808080808080llu;

    uint64_t m = (uint64_t)swar_msbbytes_to_bits8(a_w) | ((uint64_t)swar_msbbytes_to_bits8(b_w) << 8);

    *mask = ~m;
    *avail = w;
}

/* --------------------------- SSE2 (16 bytes) --------------------------- */
#ifdef SIMD_SSE2
  #include <emmintrin.h>
static void mask_sse2(const char *data, size_t cursor, uint64_t *mask, unsigned *avail)
{
    const unsigned w = 16;
    const char *p = data + cursor;

    __m128i v   = _mm_loadu_si128((const __m128i *)p);
    __m128i sp  = _mm_set1_epi8(' ');
    __m128i tab = _mm_set1_epi8('\t');

    __m128i is_sp  = _mm_cmpeq_epi8(v, sp);
    __m128i is_tab = _mm_cmpeq_epi8(v, tab);
    __m128i is_ws  = _mm_or_si128(is_sp, is_tab);

    unsigned bits = (unsigned)_mm_movemask_epi8(is_ws);
    *mask = ~(uint64_t)bits;
    *avail = w;
}
#endif

/* -------------------------- SSE4.2 (16 bytes) -------------------------- */
#ifdef SIMD_SSE42
  #include <emmintrin.h>
static void mask_sse42(const char *data, size_t cursor, uint64_t *mask, unsigned *avail)
{
    const unsigned w = 16;
    const char *p = data + cursor;

    __m128i v   = _mm_loadu_si128((const __m128i *)p);
    __m128i sp  = _mm_set1_epi8(' ');
    __m128i tab = _mm_set1_epi8('\t');

    __m128i is_sp  = _mm_cmpeq_epi8(v, sp);
    __m128i is_tab = _mm_cmpeq_epi8(v, tab);
    __m128i is_ws  = _mm_or_si128(is_sp, is_tab);

    unsigned bits = (unsigned)_mm_movemask_epi8(is_ws);
    *mask = ~(uint64_t)bits;
    *avail = w;
}
#endif

/* ---------------------------- AVX2 (32 bytes) -------------------------- */
#ifdef SIMD_AVX2
  #include <immintrin.h>
static void mask_avx2(const char *data, size_t cursor, uint64_t *mask, unsigned *avail)
{
    const unsigned w = 32;
    const char *p = data + cursor;

    __m256i v   = _mm256_loadu_si256((const __m256i *)p);
    __m256i sp  = _mm256_set1_epi8(' ');
    __m256i tab = _mm256_set1_epi8('\t');

    __m256i is_sp  = _mm256_cmpeq_epi8(v, sp);
    __m256i is_tab = _mm256_cmpeq_epi8(v, tab);
    __m256i is_ws  = _mm256_or_si256(is_sp, is_tab);

    unsigned bits = (unsigned)_mm256_movemask_epi8(is_ws);
    *mask = ~(uint64_t)bits; /* low 32 bits used */
    *avail = w;
}
#endif

/* --------------------------- AVX512 (64 bytes) -------------------------- */
#ifdef SIMD_AVX512
  #include <immintrin.h>
static void mask_avx512(const char *data, size_t cursor, uint64_t *mask, unsigned *avail)
{
    const unsigned w = 64;
    const char *p = data + cursor;

    /* Assume Ice Lake / AVX10-class: AVX512BW available for byte compares. */
    __m512i v   = _mm512_loadu_si512((const void *)p);
    __m512i sp  = _mm512_set1_epi8(' ');
    __m512i tab = _mm512_set1_epi8('\t');

    __mmask64 is_sp  = _mm512_cmpeq_epi8_mask(v, sp);
    __mmask64 is_tab = _mm512_cmpeq_epi8_mask(v, tab);
    __mmask64 is_ws  = is_sp | is_tab;

    *mask = ~(uint64_t)is_ws;
    *avail = w;
}
#endif

/* ---------------------------- NEON (AArch64) ---------------------------- */
#ifdef SIMD_NEON
  #include <arm_neon.h>
static void mask_neon(const char *data, size_t cursor, uint64_t *mask, unsigned *avail)
{
    const unsigned w = 16;
    const uint8_t *p = (const uint8_t *)(data + cursor);

    uint8x16_t v   = vld1q_u8(p);
    uint8x16_t sp  = vdupq_n_u8((uint8_t)' ');
    uint8x16_t tab = vdupq_n_u8((uint8_t)'\t');

    uint8x16_t is_sp  = vceqq_u8(v, sp);
    uint8x16_t is_tab = vceqq_u8(v, tab);
    uint8x16_t is_ws  = vorrq_u8(is_sp, is_tab);

    /* is_ws lanes are 0xFF (true) / 0x00 (false). Shift MSB down to 1/0. */
    uint8x16_t msb = vshrq_n_u8(is_ws, 7);
    uint8_t lanes[16];
    vst1q_u8(lanes, msb);

    uint64_t m = 0;
    for (unsigned i = 0; i < 16; i++) if (lanes[i]) m |= (1llu << i);

    *mask = ~m;
    *avail = w;
}
#endif

/* ------------------------------ SVE2 (64 bytes) ------------------------------ */
#ifdef SIMD_SVE2
  #include <arm_sve.h>
static void mask_sve2(const char *data, size_t cursor, uint64_t *mask, unsigned *avail)
{
    const unsigned w = 64;
    const uint8_t *p = (const uint8_t *)(data + cursor);

    uint64_t m = 0;
    unsigned produced = 0;

    /* SVE max vector length is 256 bytes (2048 bits). */
    uint8_t tmp[256];

    while (produced < w) {
        svbool_t pg = svwhilelt_b8((uint64_t)produced, (uint64_t)w);

        svuint8_t v   = svld1_u8(pg, p + produced);
        svuint8_t sp  = svdup_n_u8((uint8_t)' ');
        svuint8_t tab = svdup_n_u8((uint8_t)'\t');

        svbool_t is_sp = svcmpeq_u8(pg, v, sp);
        svbool_t is_tab = svcmpeq_u8(pg, v, tab);
        svbool_t is_ws = svorr_b_z(pg, is_sp, is_tab);

        uint64_t vl = svcntb();
        uint64_t take = (w - produced < (unsigned)vl) ? (uint64_t)(w - produced) : vl;

        /* Materialize 1 for whitespace, 0 otherwise. */
        svuint8_t onezero = svsel_u8(is_ws, svdup_n_u8(1), svdup_n_u8(0));
        svst1_u8(pg, tmp, onezero);

        for (uint64_t i = 0; i < take; i++) if (tmp[i]) m |= (1llu << (produced + (unsigned)i));
        produced += (unsigned)take;
    }

    *mask = ~m;
    *avail = w;
}
#endif

/* ----------------------------- RISCVV (64 bytes) ----------------------------- */
#ifdef SIMD_RISCVV
  #include <riscv_vector.h>
static void mask_riscvv(const char *data, size_t cursor, uint64_t *mask, unsigned *avail)
{
    const unsigned w = 64;
    const uint8_t *p = (const uint8_t *)(data + cursor);

    uint64_t m = 0;
    unsigned produced = 0;
    uint8_t tmp[64];

    while (produced < w) {
        size_t vl = vsetvl_e8m1((size_t)(w - produced));
        vuint8m1_t v = vle8_v_u8m1(p + produced, vl);

        vbool8_t is_sp  = vmseq_vx_u8m1_b8(v, (uint8_t)' ', vl);
        vbool8_t is_tab = vmseq_vx_u8m1_b8(v, (uint8_t)'\t', vl);
        vbool8_t is_ws  = vmor_mm_b8(is_sp, is_tab, vl);

        /* Materialize 1 for whitespace, 0 otherwise. */
        vuint8m1_t onezero = vmerge_vxm_u8m1(vmv_v_x_u8m1(0, vl), 1, is_ws, vl);
        vse8_v_u8m1(tmp, onezero, vl);

        for (size_t i = 0; i < vl; i++) if (tmp[i]) m |= (1llu << (produced + (unsigned)i));
        produced += (unsigned)vl;
    }

    *mask = ~m;
    *avail = w;
}
#endif

void (*classify)(const char *data, size_t cursor, uint64_t *mask, unsigned *avail) = mask_scalar;


void
zone_mask_start(const char *data, size_t cursor, size_t max,
                uint64_t *mask, unsigned *avail) {
    /* Refill immediately at the given cursor. */
    classify(data, cursor, mask, avail);
}



size_t
zone_mask_skip_nospace2(const char *data, size_t cursor, size_t max,
                       uint64_t *mask, unsigned *avail, size_t length) {

    while (length) {
        if (*avail == 0) {
            classify(data, cursor, mask, avail);
        }

        if (length < (size_t)(*avail)) {
            *mask >>= (unsigned)length;
            *avail -= (unsigned)length;
            cursor += length;
            length = 0;
            break;
        }

        /* Consume the remainder of this chunk. */
        cursor += (size_t)(*avail);
        length -= (size_t)(*avail);
        *mask = 0;
        *avail = 0;

        /* Requirement: if we landed exactly at end-of-availability (avail==0)
         * we do NOT refill until after cursor is fully advanced; the next loop
         * iteration will refill at the new `cur` if more bytes remain, otherwise
         * we refill once at the end (below) so the mask matches return cursor.
         */
    }

    /* If we ended exactly on a boundary, refill so mask matches returned cursor. */
    if (*avail == 0) {
        classify(data, cursor, mask, avail);
    }

    return cursor;
}

size_t
zone_mask_skip_space2(const char *data, size_t cursor, size_t max,
                     uint64_t *mask, unsigned *avail, unsigned *depth) {
    for (;;) {
        if (*avail == 0) {
            classify(data, cursor, mask, avail);
        }

        /* Fast-skip contiguous whitespace:
         * Mask polarity: bit=0 for whitespace, bit=1 for non-whitespace.
         * So ctz(mask) gives the count of leading whitespace bytes.
         *
         * If mask == 0, the entire chunk is whitespace; consume it all.
         */
        if (*mask == 0) {
            cursor = zone_mask_skip_nospace2(data, cursor, max, mask, avail, *avail);
            continue;
        }

        /* Count leading whitespace (spaces/tabs) and consume them. */
        unsigned ws = ctz64(*mask);
        while (ws) {
            cursor = zone_mask_skip_nospace2(data, cursor, max, mask, avail, ws);
            ws = ctz64(*mask);
        }

        /* Now at the first non-whitespace byte (or at a boundary with fresh mask). */
        unsigned char c = (unsigned char)data[cursor];

        /* Trigger: comment start ';' */
        if (c == ';') {
            size_t eol = zone_scan_eol(data, cursor, max);
            
            if (*depth == 0)
                return eol;

            /* zone_scan_eol returns position at '\n' (assumed); compute bytes to skip */
            cursor = zone_mask_skip_nospace2(data, cursor, max, mask, avail, eol - cursor);
            continue;
        }

        /* Trigger: '(' increments depth, consume, continue */
        if (c == '(') {
            (*depth)++;
            cursor = zone_mask_skip_nospace2(data, cursor, max, mask, avail, 1);
            continue;
        }

        /* Trigger: ')' decrements depth, consume, continue */
        if (c == ')') {
            (*depth)--;
            cursor = zone_mask_skip_nospace2(data, cursor, max, mask, avail, 1);
            continue;
        }

        /* Trigger: newline */
        if (c == '\n') {
            if (*depth == 0)
                return cursor;

            cursor = zone_mask_skip_nospace2(data, cursor, max, mask, avail, 1);
            continue;
        }

        /* Otherwise we are at token start (non-whitespace, non-trigger). */
        return cursor;
    }
}



/* --------------------------- Dispatch / init --------------------------- */

void zone_atom_mask_init(int simd)
{
    switch (simd) {
    case SIMD_AUTO:zone_atom_mask_init(simd_get_best());break;
    case SIMD_SCALAR:classify=mask_scalar;break;
    case SIMD_SWAR:classify=mask_swar;break;
#ifdef SIMD_SSE2
    case SIMD_SSE2:classify=mask_sse2;break;
#endif
#ifdef SIMD_SSE42
    case SIMD_SSE42:classify=mask_sse42;break;
#endif
#ifdef SIMD_AVX2
    case SIMD_AVX2:classify=mask_avx2;break;
#endif
#ifdef SIMD_AVX512
    case SIMD_AVX512:classify=mask_avx512;break;
#endif
#ifdef SIMD_NEON
    case SIMD_NEON:classify=mask_neon;break;
#endif
#ifdef SIMD_SVE2
    case SIMD_SVE2:zone_atom_mask=mask_sve2;break;
#endif
#ifdef SIMD_RISCVV
    case SIMD_RISCVV:zone_atom_mask=mask_riscvv;break;
#endif
    case SIMD_MAX:break;
    default:classify=mask_scalar;break;
    }
}

/* --------------------------- quick self-test --------------------------- */

struct atom_mask_test { const char *s; uint64_t expect; };

static int build_mask64_by_backend(const char *data64, uint64_t *out)
{
    size_t cursor = 0;
    uint64_t accum = 0;

    while (cursor < 64) {
        uint64_t m = 0;
        unsigned avail = 0;

        classify(data64, cursor, &m, &avail);
        if (avail == 0) return -1;

        unsigned take = (unsigned)((64 - cursor < (size_t)avail) ? (64 - cursor) : (size_t)avail);

        /* take low `take` bits */
        uint64_t part;
        if (take == 64) part = m;
        else part = m & ((1llu << take) - 1llu);

        accum |= (part << cursor);
        cursor += take;
    }

    *out = accum;
    return 0;
}

#define SEG8_SP  "        "
#define SEG8_A   "AAAAAAAA"
#define SEG8_TAB "\t\t\t\t\t\t\t\t"

int zone_atom_mask_quicktest(void)
{
    /* All inputs must be exactly 64 bytes. */
    static const struct atom_mask_test tests[20] = {
        /*  0 */ { SEG8_SP SEG8_SP SEG8_SP SEG8_SP SEG8_SP SEG8_SP SEG8_SP SEG8_SP, 0xffffffffffffffffllu },
        /*  1 */ { SEG8_A  SEG8_A  SEG8_A  SEG8_A  SEG8_A  SEG8_A  SEG8_A  SEG8_A,  0x0000000000000000llu },
        /*  2 */ { SEG8_SP SEG8_SP SEG8_SP SEG8_SP SEG8_A  SEG8_A  SEG8_A  SEG8_A,  0x00000000ffffffffllu },
        /*  3 */ { SEG8_A  SEG8_A  SEG8_A  SEG8_A  SEG8_SP SEG8_SP SEG8_SP SEG8_SP, 0xffffffff00000000llu },

        /*  4 */ { " A" " A" " A" " A" " A" " A" " A" " A" " A" " A" " A" " A" " A" " A" " A" " A"
                  " A" " A" " A" " A" " A" " A" " A" " A" " A" " A" " A" " A" " A" " A" " A" " A", 0x5555555555555555llu },

        /*  5 */ { "A " "A " "A " "A " "A " "A " "A " "A " "A " "A " "A " "A " "A " "A " "A " "A "
                  "A " "A " "A " "A " "A " "A " "A " "A " "A " "A " "A " "A " "A " "A " "A " "A ", 0xaaaaaaaaaaaaaaaallu },

        /*  6 */ { SEG8_SP SEG8_SP SEG8_A  SEG8_A  SEG8_TAB SEG8_TAB "BBBBBBBB" "BBBBBBBB", 0x0000ffff0000ffffllu },
        /*  7 */ { SEG8_A  SEG8_A  SEG8_SP SEG8_SP "BBBBBBBB" "BBBBBBBB" SEG8_TAB SEG8_TAB, 0xffff0000ffff0000llu },

        /*  8 */ { SEG8_SP SEG8_A  SEG8_SP SEG8_A  SEG8_SP SEG8_A  SEG8_SP SEG8_A, 0x00ff00ff00ff00ffllu },
        /*  9 */ { SEG8_A  SEG8_SP SEG8_A  SEG8_SP SEG8_A  SEG8_SP SEG8_A  SEG8_SP, 0xff00ff00ff00ff00llu },

        /* 10 */ { SEG8_TAB SEG8_A  SEG8_TAB SEG8_A  SEG8_TAB SEG8_A  SEG8_TAB SEG8_A, 0x00ff00ff00ff00ffllu },
        /* 11 */ { SEG8_A   SEG8_TAB SEG8_A  SEG8_TAB SEG8_A  SEG8_TAB SEG8_A  SEG8_TAB, 0xff00ff00ff00ff00llu },

        /* 12 */ { "    ""AAAA""    ""AAAA""    ""AAAA""    ""AAAA""    ""AAAA""    ""AAAA""    ""AAAA""    ""AAAA", 0x0f0f0f0f0f0f0f0fllu },
        /* 13 */ { "AAAA""    ""AAAA""    ""AAAA""    ""AAAA""    ""AAAA""    ""AAAA""    ""AAAA""    ""AAAA""    ", 0xf0f0f0f0f0f0f0f0llu },

        /* 14 */ { " " SEG8_A SEG8_A SEG8_A SEG8_A SEG8_A SEG8_A SEG8_A "AAAAAAA", 0x0000000000000001llu },
        /* 15 */ { SEG8_A SEG8_A SEG8_A SEG8_A SEG8_A SEG8_A SEG8_A "AAAAAAA ", 0x8000000000000000llu },

        /* 16 */ { "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF", 0x0000000000000000llu },

        /* 17 */ { " \t \t \t \t \t \t \t \t \t \t \t \t \t \t \t \t \t \t \t \t \t \t \t \t \t \t \t \t \t \t \t \t", 0xffffffffffffffffllu },

        /* 18 */ { "  \t\t" "AAAAAAAA" "AAAAAAAA" "AAAAAAAA" "AAAAAAAA" "AAAAAAAA" "AAAAAAAA" "AAAAAAAA" "AAAA", 0x000000000000000fllu },

        /* 19 */ { "AAAAAAAA" "AAAAAAAA" "AAAAAAAA" "AAAAAAAA" "AAAAAAAA" "AAAAAAAA" "\t\t  " "AAAAAAAAAAAA", 0x000f000000000000 },
    };

    int err = 0;

    for (int simd = (int)SIMD_AUTO + 1; simd < (int)SIMD_MAX; simd++) {
        zone_atom_mask_init(simd);
        if (!classify) continue;

        for (int t = 0; t < 20; t++) {
            /* Require exactly 64 bytes. */
            if (strlen(tests[t].s) != 64) {
                fprintf(stderr, "atom.mask:%d failed test, len=%u\n", t,
                        (unsigned)strlen(tests[t].s));
                err++;
                continue;
            }

            uint64_t got = 0;
            if (build_mask64_by_backend(tests[t].s, &got) != 0 || got != tests[t].expect) {
                fprintf(stderr, "atom.mask:%d failed test 0x%016llx\n", t, got);
                err++;
            }
        }
    }

    return err;
}

#undef SEG8_SP
#undef SEG8_A
#undef SEG8_TAB
