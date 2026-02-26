/* zone-parse-header2.c
 *
 * Happy-path header parser after owner name:  [TTL] [CLASS] TYPE
 *
 * Core design:
 * - ONE classify at entry (64-byte window). If we run out of window => slow path.
 * - Masks are “desired chars = 0 bits” so ctz64() finds lengths quickly:
 *     spaces mask: 0 for ' ' or '\t'
 *     alnum  mask: 0 for [A-Za-z0-9]
 * - We do NOT handle comments, parentheses, quotes, etc. Any “other” anywhere in
 *   the consumed prefix triggers slow path (checked once at end).
 * - Any parse failure => slow path (no errors produced here).
 * - On success: append wire header fields at (out->write.buf + out->write.length):
 *     rrtype(16), rrclass(16), rrttl(32), big-endian; then +8 to write.length and wire.len.
 *
 * Runtime dispatch:
 * - Default classifier is scalar.
 * - zone_parse_header2_init(int simd) selects classifier via switch.
 * - If simd==0 (SIMD_AUTO), it recurses with simd_get_best().
 *
 * Assumptions:
 * - Classifier functions DO NOT check max and may read past end (caller pads).
 * - This file uses only the first 64 bytes starting at cursor for happy path.
 */

#include <stddef.h>
#include <stdint.h>

#include "zone-parse.h"
#include "util-simd.h"

struct hdrmasks {
    uint64_t spaces; /* bit=0 for (' ' or '\t'), bit=1 otherwise */
    uint64_t alnum;  /* bit=0 for [A-Za-z0-9],  bit=1 otherwise */
    unsigned avail;  /* optional; not required (derived) */
};


/* ------------ wire write helpers (big-endian) ------------ */

static inline void store_be16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v >> 0);
}
static inline void store_be32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)(v >> 0);
}

/* “other” = neither space/tab nor alnum */
static inline uint64_t hdr_other_mask(const struct hdrmasks *m) {
    return (m->spaces & m->alnum);
}

/* ------------ scalar classifier (reference + default) ------------ */

/*static inline uint8_t is_space_tab_u8(uint8_t c) {
    return (c == (uint8_t)' ') || (c == (uint8_t)'\t');
}*/
/*
static inline uint8_t is_alnum_u8(uint8_t c) {
    uint8_t lo = (uint8_t)(c | 0x20);
    return ((c >= (uint8_t)'0' && c <= (uint8_t)'9') ||
            (lo >= (uint8_t)'a' && lo <= (uint8_t)'z'));
}*/

#if 0
static struct hdrmasks
hdr_classify_scalar64(const char *data, size_t cursor, size_t max)
{
    (void)max;
    const uint8_t *p = (const uint8_t *)(data + cursor);
    uint64_t spaces = 0; /* 0 for desired, 1 otherwise */
    uint64_t alnum  = 0;

    for (unsigned i = 0; i < 16; i++) {
        uint8_t c = p[i];
        if (!is_space_tab_u8(c)) spaces |= (1ull << i);
        if (!is_alnum_u8(c))     alnum  |= (1ull << i);
    }

    struct hdrmasks m;
    m.spaces = spaces | 0x10000;
    m.alnum  = alnum | 0x10000;
    m.avail  = 16;
    return m;
}
#endif

/*
 * Table encoding:
 *
 * bit 0 (0x01) = NONSPACE   (1 if NOT ' ' or '\t')
 * bit 1 (0x02) = NONALNUM   (1 if NOT [A-Za-z0-9])
 *
 * So:
 *   0x02 = space/tab
 *   0x01 = alnum
 *   0x03 = everything else
 */

static const uint8_t hdr_class_table[256] = {
    /* 0x00–0x1F */
    0x03,0x03,0x03,0x03,0x03,0x03,0x03,0x03,
    0x03,0x02,0x03,0x03,0x03,0x03,0x03,0x03,
    0x03,0x03,0x03,0x03,0x03,0x03,0x03,0x03,
    0x03,0x03,0x03,0x03,0x03,0x03,0x03,0x03,

    /* 0x20–0x2F */
    0x02,0x03,0x03,0x03,0x03,0x03,0x03,0x03,
    0x03,0x03,0x03,0x03,0x03,0x03,0x03,0x03,

    /* 0x30–0x3F  '0'–'9' */
    0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
    0x01,0x01,0x03,0x03,0x03,0x03,0x03,0x03,

    /* 0x40–0x4F  'A'–'O' */
    0x03,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
    0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,

    /* 0x50–0x5F  'P'–'Z' */
    0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
    0x01,0x01,0x01,0x03,0x03,0x03,0x03,0x03,

    /* 0x60–0x6F  'a'–'o' */
    0x03,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
    0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,

    /* 0x70–0x7F  'p'–'z' */
    0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
    0x01,0x01,0x01,0x03,0x03,0x03,0x03,0x03,

    /* 0x80–0xFF (all non-ASCII treated as other) */
    0x03,0x03,0x03,0x03,0x03,0x03,0x03,0x03,
    0x03,0x03,0x03,0x03,0x03,0x03,0x03,0x03,
    0x03,0x03,0x03,0x03,0x03,0x03,0x03,0x03,
    0x03,0x03,0x03,0x03,0x03,0x03,0x03,0x03,

    0x03,0x03,0x03,0x03,0x03,0x03,0x03,0x03,
    0x03,0x03,0x03,0x03,0x03,0x03,0x03,0x03,
    0x03,0x03,0x03,0x03,0x03,0x03,0x03,0x03,
    0x03,0x03,0x03,0x03,0x03,0x03,0x03,0x03,

    0x03,0x03,0x03,0x03,0x03,0x03,0x03,0x03,
    0x03,0x03,0x03,0x03,0x03,0x03,0x03,0x03,
    0x03,0x03,0x03,0x03,0x03,0x03,0x03,0x03,
    0x03,0x03,0x03,0x03,0x03,0x03,0x03,0x03,

    0x03,0x03,0x03,0x03,0x03,0x03,0x03,0x03,
    0x03,0x03,0x03,0x03,0x03,0x03,0x03,0x03,
    0x03,0x03,0x03,0x03,0x03,0x03,0x03,0x03,
    0x03,0x03,0x03,0x03,0x03,0x03,0x03,0x03
};


/*
 * Scalar 16-byte classifier
 * - Single table lookup per byte
 * - No comparisons
 * - Exactly 16 bytes classified
 */

static inline struct hdrmasks
hdr_classify_scalar64(const char *data, size_t cursor, size_t max)
{
    (void)max;

    const uint8_t *p = (const uint8_t *)(data + cursor);

    uint64_t spaces = 0;
    uint64_t alnum  = 0;

    for (unsigned i = 0; i < 16; i++) {
        uint8_t f = hdr_class_table[p[i]];
        spaces |= (uint64_t)( f        & 1u) << i;      /* NONSPACE  */
        alnum  |= (uint64_t)( f       & 2u) << i;      /* NONALNUM  */
    }
    alnum >>= 1;

    struct hdrmasks m;
    m.spaces = spaces;
    m.alnum  = alnum;
    m.avail  = 16;
    return m;
}
/* ------------ SIMD classifiers (64-byte window) ------------ */
/* These all produce the SAME mask convention as scalar:
 *   spaces bit=1 => NOT (' ' or '\t')
 *   alnum  bit=1 => NOT alnum
 */

static struct hdrmasks hdr_classify_swar64(const char *d, size_t c, size_t m) { return hdr_classify_scalar64(d,c,m); }

#if defined(SIMD_SSE2) || defined(SIMD_SSE42) || defined(SIMD_AVX2) || defined(SIMD_AVX512)
#include <immintrin.h>
#endif

#ifdef SIMD_SSE2
static inline __m128i mm_set1_u8(char x) { return _mm_set1_epi8((char)x); }

/* unsigned range check for u8 using signed compares: (x >= lo && x <= hi) */
static inline __m128i mm_inrange_u8(__m128i x, uint8_t lo, uint8_t hi) {
    const __m128i bias = _mm_set1_epi8((char)0x80);
    __m128i xb = _mm_add_epi8(x, bias);
    __m128i lob = _mm_set1_epi8((char)(lo ^ 0x80));
    __m128i hib = _mm_set1_epi8((char)(hi ^ 0x80));

    /* xb >= lob  <=> xb > (lob-1) */
    __m128i lobm1 = _mm_sub_epi8(lob, _mm_set1_epi8(1));
    __m128i ge = _mm_cmpgt_epi8(xb, lobm1);

    /* xb <= hib <=> (hib+1) > xb */
    __m128i hip1 = _mm_add_epi8(hib, _mm_set1_epi8(1));
    __m128i le = _mm_cmpgt_epi8(hip1, xb);

    return _mm_and_si128(ge, le);
}

static struct hdrmasks
hdr_classify_sse2_64(const char *data, size_t cursor, size_t max)
{
    (void)max;
    const uint8_t *p = (const uint8_t *)(data + cursor);

    uint64_t spaces = 0;
    uint64_t alnum  = 0;

    const __m128i v_space = mm_set1_u8(' ');
    const __m128i v_tab   = mm_set1_u8('\t');
    const __m128i v_0x20  = mm_set1_u8((char)0x20);

    for (unsigned blk = 0; blk < 1; blk++) {
        __m128i v = _mm_loadu_si128((const __m128i *)(p + blk*16));

        /* spaces desired: ' ' or '\t' */
        __m128i eq_sp = _mm_cmpeq_epi8(v, v_space);
        __m128i eq_tb = _mm_cmpeq_epi8(v, v_tab);
        __m128i is_sp = _mm_or_si128(eq_sp, eq_tb);
        unsigned sp_mask = (unsigned)_mm_movemask_epi8(is_sp); /* 1 where desired */
        unsigned nonspace = (~sp_mask) & 0xFFFFu;              /* 1 where NOT desired */
        spaces |= ((uint64_t)nonspace) << (blk*16);

        /* alnum desired: digit OR alpha */
        __m128i is_digit = mm_inrange_u8(v, (uint8_t)'0', (uint8_t)'9');
        __m128i v_lo = _mm_or_si128(v, v_0x20);
        __m128i is_alpha = mm_inrange_u8(v_lo, (uint8_t)'a', (uint8_t)'z');
        __m128i is_an = _mm_or_si128(is_digit, is_alpha);
        unsigned an_mask = (unsigned)_mm_movemask_epi8(is_an); /* 1 where desired */
        unsigned nonalnum = (~an_mask) & 0xFFFFu;
        alnum |= ((uint64_t)nonalnum) << (blk*16);
    }

    struct hdrmasks m;
    m.spaces = spaces;
    m.alnum  = alnum;
    m.avail  = 16;
    return m;
}
#endif /* SIMD_SSE2 */

#ifdef SIMD_SSE42
/* SSE4.2 version: same as SSE2 here (classification needs only SSE2 ops). */
static struct hdrmasks
hdr_classify_sse42_64(const char *data, size_t cursor, size_t max)
{
#ifdef SIMD_SSE2
    return hdr_classify_sse2_64(data, cursor, max);
#else
    return hdr_classify_scalar64(data, cursor, max);
#endif
}
#endif /* SIMD_SSE42 */

#ifdef SIMD_AVX2
static inline __m256i mm256_set1_u8(char x) { return _mm256_set1_epi8((char)x); }

static inline __m256i mm256_inrange_u8(__m256i x, uint8_t lo, uint8_t hi) {
    const __m256i bias = _mm256_set1_epi8((char)0x80);
    __m256i xb = _mm256_add_epi8(x, bias);
    __m256i lob = _mm256_set1_epi8((char)(lo ^ 0x80));
    __m256i hib = _mm256_set1_epi8((char)(hi ^ 0x80));

    __m256i lobm1 = _mm256_sub_epi8(lob, _mm256_set1_epi8(1));
    __m256i ge = _mm256_cmpgt_epi8(xb, lobm1);

    __m256i hip1 = _mm256_add_epi8(hib, _mm256_set1_epi8(1));
    __m256i le = _mm256_cmpgt_epi8(hip1, xb);

    return _mm256_and_si256(ge, le);
}

static struct hdrmasks
hdr_classify_avx2_64(const char *data, size_t cursor, size_t max)
{
    (void)max;
    const uint8_t *p = (const uint8_t *)(data + cursor);

    uint64_t spaces = 0;
    uint64_t alnum  = 0;

    const __m256i v_space = mm256_set1_u8(' ');
    const __m256i v_tab   = mm256_set1_u8('\t');
    const __m256i v_0x20  = mm256_set1_u8((char)0x20);

    for (unsigned blk = 0; blk < 2; blk++) {
        __m256i v = _mm256_loadu_si256((const __m256i *)(p + blk*32));

        __m256i eq_sp = _mm256_cmpeq_epi8(v, v_space);
        __m256i eq_tb = _mm256_cmpeq_epi8(v, v_tab);
        __m256i is_sp = _mm256_or_si256(eq_sp, eq_tb);
        uint32_t sp_mask = (uint32_t)_mm256_movemask_epi8(is_sp);
        uint32_t nonspace = ~sp_mask;
        spaces |= ((uint64_t)nonspace) << (blk*32);

        __m256i is_digit = mm256_inrange_u8(v, (uint8_t)'0', (uint8_t)'9');
        __m256i v_lo = _mm256_or_si256(v, v_0x20);
        __m256i is_alpha = mm256_inrange_u8(v_lo, (uint8_t)'a', (uint8_t)'z');
        __m256i is_an = _mm256_or_si256(is_digit, is_alpha);
        uint32_t an_mask = (uint32_t)_mm256_movemask_epi8(is_an);
        uint32_t nonalnum = ~an_mask;
        alnum |= ((uint64_t)nonalnum) << (blk*32);
    }

    struct hdrmasks m;
    m.spaces = spaces;
    m.alnum  = alnum;
    m.avail  = 64;
    return m;
}
#endif /* SIMD_AVX2 */

#ifdef SIMD_AVX512
/* AVX-512BW needed for byte compares; assume your build sets it when SIMD_AVX512 defined. */
static struct hdrmasks
hdr_classify_avx512_64(const char *data, size_t cursor, size_t max)
{
    (void)max;
    const __m512i v = _mm512_loadu_si512((const void *)(data + cursor));

    /* spaces desired: ' ' or '\t' */
    const __m512i v_space = _mm512_set1_epi8(' ');
    const __m512i v_tab   = _mm512_set1_epi8('\t');
    __mmask64 is_sp = _mm512_cmpeq_epi8_mask(v, v_space) | _mm512_cmpeq_epi8_mask(v, v_tab);
    uint64_t spaces = ~((uint64_t)is_sp); /* 1 where NOT desired */

    /* alnum desired: digit or alpha */
    const __m512i v_0x20 = _mm512_set1_epi8((char)0x20);
    __m512i v_lo = _mm512_or_si512(v, v_0x20);

    __mmask64 is_digit =
        _mm512_cmpge_epu8_mask(v, _mm512_set1_epi8('0')) &
        _mm512_cmple_epu8_mask(v, _mm512_set1_epi8('9'));

    __mmask64 is_alpha =
        _mm512_cmpge_epu8_mask(v_lo, _mm512_set1_epi8('a')) &
        _mm512_cmple_epu8_mask(v_lo, _mm512_set1_epi8('z'));

    uint64_t alnum = ~((uint64_t)(is_digit | is_alpha)); /* 1 where NOT desired */

    struct hdrmasks m;
    m.spaces = spaces;
    m.alnum  = alnum;
    m.avail  = 64;
    return m;
}
#endif /* SIMD_AVX512 */

#ifdef SIMD_NEON
#include <arm_neon.h>
/* AArch64 NEON: cheap 16-byte classifier for zone_parse_header2
 *
 * Window: 16 bytes
 * Output convention (desired chars => 0 bits):
 *   m.spaces bit=1 => NOT (' ' or '\t')
 *   m.alnum  bit=1 => NOT [A-Za-z0-9]
 *   m.avail = 16
 *
 * Key point: avoid “movemask via store+scalar”.
 * We build a 16-bit mask using a power-of-two multiply-add reduction:
 *   - keep per-lane bits as {1,2,4,8,16,32,64,128} repeated per 8-lane half
 *   - AND with 0xFF/0x00 predicate vector
 *   - pairwise-add to collapse each half into a single byte
 *   - combine into 16-bit mask
 */
#if defined(__aarch64__) || defined(_M_ARM64)

#include <arm_neon.h>
#include <stdint.h>
#include <stddef.h>


/* Fast NEON “movemask” for 16 lanes:
 * input lanes are 0xFF for true, 0x00 for false (i.e., compare result).
 *
 * This follows the pattern you posted:
 *   - shift right by 7 to get 0/1
 *   - shift each lane by {0..7} into its bit position
 *   - horizontal add each 8-lane half to get byte masks
 */
static inline uint16_t
neon_movemask_u8(uint8x16_t cmp_ff00) {
    uint8x16_t b = vshrq_n_u8(cmp_ff00, 7);
    const int8x8_t shifts = (int8x8_t){0,1,2,3,4,5,6,7};
    uint8x8_t lo = vshl_u8(vget_low_u8(b), shifts);
    uint8x8_t hi = vshl_u8(vget_high_u8(b), shifts);
    return (uint16_t)vaddv_u8(lo) | ((uint16_t)vaddv_u8(hi) << 8);
}

/* NEON classifier for 32 bytes (two 16-byte vectors).
 *
 * Mask convention: “desired chars => 0 bits”
 * - spaces mask bit=0 for space/tab
 * - alnum  mask bit=0 for A-Z a-z 0-9
 *
 * So:
 *   spaces = ~movemask(is_space_or_tab)  (low 32 bits used)
 *   alnum  = ~movemask(is_alnum)         (low 32 bits used)
 */
static inline struct hdrmasks
hdr_classify_neon_64(const char *data, size_t cursor, size_t max) {
    
    const uint8_t *p = (const uint8_t *)(data + cursor);

    uint8x16_t v0 = vld1q_u8(p + 0);
    uint8x16_t v1 = vld1q_u8(p + 16);

    /* --- spaces: ' ' or '\t' --- */
    uint8x16_t sp0 = vceqq_u8(v0, vdupq_n_u8((uint8_t)' '));
    uint8x16_t tb0 = vceqq_u8(v0, vdupq_n_u8((uint8_t)'\t'));
    uint8x16_t is_space0 = vorrq_u8(sp0, tb0);

    uint8x16_t sp1 = vceqq_u8(v1, vdupq_n_u8((uint8_t)' '));
    uint8x16_t tb1 = vceqq_u8(v1, vdupq_n_u8((uint8_t)'\t'));
    uint8x16_t is_space1 = vorrq_u8(sp1, tb1);

    uint16_t space_ok0 = neon_movemask_u8(is_space0); /* 1 where space/tab */
    uint16_t space_ok1 = neon_movemask_u8(is_space1);

    /* --- alnum: digit OR alpha --- */
    /* digits */
    uint8x16_t d0 = vandq_u8(vcgeq_u8(v0, vdupq_n_u8((uint8_t)'0')),
                            vcleq_u8(v0, vdupq_n_u8((uint8_t)'9')));
    uint8x16_t d1 = vandq_u8(vcgeq_u8(v1, vdupq_n_u8((uint8_t)'0')),
                            vcleq_u8(v1, vdupq_n_u8((uint8_t)'9')));

    /* alpha: fold to lowercase via OR 0x20, then compare 'a'..'z' */
    uint8x16_t v0lo = vorrq_u8(v0, vdupq_n_u8((uint8_t)0x20));
    uint8x16_t v1lo = vorrq_u8(v1, vdupq_n_u8((uint8_t)0x20));

    uint8x16_t a0 = vandq_u8(vcgeq_u8(v0lo, vdupq_n_u8((uint8_t)'a')),
                            vcleq_u8(v0lo, vdupq_n_u8((uint8_t)'z')));
    uint8x16_t a1 = vandq_u8(vcgeq_u8(v1lo, vdupq_n_u8((uint8_t)'a')),
                            vcleq_u8(v1lo, vdupq_n_u8((uint8_t)'z')));

    uint8x16_t is_alnum0 = vorrq_u8(d0, a0);
    uint8x16_t is_alnum1 = vorrq_u8(d1, a1);

    uint16_t alnum_ok0 = neon_movemask_u8(is_alnum0); /* 1 where alnum */
    uint16_t alnum_ok1 = neon_movemask_u8(is_alnum1);

    uint32_t space_ok32 = (uint32_t)space_ok0 | ((uint32_t)space_ok1 << 16);
    uint32_t alnum_ok32  = (uint32_t)alnum_ok0  | ((uint32_t)alnum_ok1  << 16);

    struct hdrmasks m;
    m.spaces = (uint64_t)(~space_ok32) & 0xFFFFFFFFull; /* 1 where NOT space/tab */
    m.alnum  = (uint64_t)(~alnum_ok32)  & 0xFFFFFFFFull; /* 1 where NOT alnum */
    m.avail  = 32;
    return m;
}

#endif /* AArch64 */
#endif /* SIMD_NEON */

#ifdef SIMD_SVE2
/* Best-effort SVE2: do SVE compares/loads but pack mask via store+scalar.
 * (You can later replace packing with a faster predicate-to-bitmask routine.)
 */
#include <arm_sve.h>

static struct hdrmasks
hdr_classify_sve2_64(const char *data, size_t cursor, size_t max)
{
    (void)max;

    uint8_t buf[64];
    /* Load 64 bytes using SVE (VL may be >=64, so do it in chunks). */
    unsigned done = 0;
    while (done < 64) {
        svbool_t pg = svwhilelt_b8((uint64_t)done, 64);
        svuint8_t v = svld1_u8(pg, (const uint8_t *)(data + cursor + done));
        svst1_u8(pg, buf + done, v);
        done += svcntb();
        if (svcntb() == 0) break;
    }

    /* Scalar pack into masks (same convention). */
    uint64_t spaces = 0, alnum = 0;
    for (unsigned i = 0; i < 64; i++) {
        uint8_t c = buf[i];
        if (!is_space_tab_u8(c)) spaces |= (1ull << i);
        if (!is_alnum_u8(c))     alnum  |= (1ull << i);
    }

    struct hdrmasks m;
    m.spaces = spaces;
    m.alnum  = alnum;
    m.avail  = 64;
    return m;
}
#endif /* SIMD_SVE2 */

#ifdef SIMD_RISCVV
/* Best-effort RVV: use RVV loads then store+scalar pack.
 * Replace later with real RVV bitmask packing if you want.
 */
#include <riscv_vector.h>

static struct hdrmasks
hdr_classify_riscvv_64(const char *data, size_t cursor, size_t max)
{
    (void)max;

    uint8_t buf[64];
    size_t off = 0;
    while (off < 64) {
        size_t vl = vsetvl_e8m1(64 - off);
        vuint8m1_t v = vle8_v_u8m1((const uint8_t *)(data + cursor + off), vl);
        vse8_v_u8m1(buf + off, v, vl);
        off += vl;
    }

    uint64_t spaces = 0, alnum = 0;
    for (unsigned i = 0; i < 64; i++) {
        uint8_t c = buf[i];
        if (!is_space_tab_u8(c)) spaces |= (1ull << i);
        if (!is_alnum_u8(c))     alnum  |= (1ull << i);
    }

    struct hdrmasks m;
    m.spaces = spaces;
    m.alnum  = alnum;
    m.avail  = 64;
    return m;
}
#endif /* SIMD_RISCVV */

/* ------------ runtime dispatch ------------ */

typedef struct hdrmasks (*hdr_classify_fn)(const char *data, size_t cursor, size_t max);

static hdr_classify_fn g_hdr_classify = hdr_classify_scalar64; /* scalar by default */

void
zone_parse_header2_init(int simd)
{
    if (simd == 0) {
        zone_parse_header2_init(simd_get_best());
        return;
    }

    switch ((simd_backend_t)simd) {
    default:
    case SIMD_SCALAR:
        g_hdr_classify = hdr_classify_scalar64;
        break;

    case SIMD_SWAR:
        g_hdr_classify = hdr_classify_swar64;
        break;

#ifdef SIMD_SSE2
    case SIMD_SSE2:
        g_hdr_classify = hdr_classify_sse2_64;
        break;
#endif
#ifdef SIMD_SSE42
    case SIMD_SSE42:
        g_hdr_classify = hdr_classify_sse42_64;
        break;
#endif
#ifdef SIMD_AVX2
    case SIMD_AVX2:
        g_hdr_classify = hdr_classify_avx2_64;
        break;
#endif
#ifdef SIMD_AVX512
    case SIMD_AVX512:
        g_hdr_classify = hdr_classify_avx512_64;
        break;
#endif
#ifdef SIMD_NEON
    case SIMD_NEON:
        g_hdr_classify = hdr_classify_neon_64;
        break;
#endif
#ifdef SIMD_SVE2
    case SIMD_SVE2:
        g_hdr_classify = hdr_classify_sve2_64;
        break;
#endif
#ifdef SIMD_RISCVV
    case SIMD_RISCVV:
        g_hdr_classify = hdr_classify_riscvv_64;
        break;
#endif
    }
}

static int is_digit(char c) {
    return ('0' <= c && c <= '9');
}
/* ------------ happy-path header parse (single classify, straight line) ------------ */

size_t
zone_parse_header2(const char *data, size_t cursor, size_t max,
                   struct wire_record_t *out,
                   unsigned *depth)
{
    size_t orig_cursor = cursor;
    int err = 0;
    unsigned rrttl = out->state.default_ttl;
    unsigned rrclass = 1; /* default IN */
    unsigned rrtype = 0;
        
    /*
     * Exactly one classify
     */
    struct hdrmasks m = g_hdr_classify(data, cursor, max);
    
    /* Helpers: consume within 64-byte window only */
#define NEED_IN_WINDOW(_off_) do { if ((_off_) >= 64) goto slow; } while (0)
#define SPACES_AT(_off_)      (m.spaces >> (_off_))
#define ALNUM_AT(_off_)       (m.alnum  >> (_off_))
    
    size_t off = 0;
    
    /*
     * skip leading space
     */
    unsigned length = ctz64(SPACES_AT(off));
    off += length;
    //NEED_IN_WINDOW(off);
    
    length = ctz64(ALNUM_AT(off));
    
    /*
     * TTL
     */
    if (is_digit(data[cursor + off])) {
        parse_ttl_fast(data, cursor + off,
                          max,
                          &rrttl,
                          &err);

        /* skip token */
        off += length;
        //NEED_IN_WINDOW(off);
        
        /* skip space */
        length = ctz64(SPACES_AT(off));
        off += length;
        //NEED_IN_WINDOW(off);
        
        /* next token length */
        length = ctz64(ALNUM_AT(off));
    }
        

    unsigned idx;
    
    
    /*
     * CLASS
     */
    if (length == 2 && data[cursor+off] == 'I' && data[cursor+off+1] == 'N') {
        /* happy path */
        idx = 1;
        rrtype = 1;
    } else {
        idx = zone_type2_lookup(data + cursor + off,
                                    length,
                                    &rrtype);
    }
    if (idx < 4) {
        err |= (idx == 0);
        
        /* it’s CLASS */
        rrclass = rrtype;
        
        /* skip token */
        off += length;
        //NEED_IN_WINDOW(off);
        
        /* skip space */
        length = ctz64(SPACES_AT(off));
        off += length;
        //NEED_IN_WINDOW(off);
        
        /* next token */
        length = ctz64(ALNUM_AT(off));
        
        idx = zone_type2_lookup(data + cursor + off,
                                         length,
                                         &rrtype);
    }
    out->rrtype.value = rrtype;
    out->rrtype.idx = idx;
    
    /* skip token */
    off += length;
    //NEED_IN_WINDOW(off);

    /* skip space */
    length = ctz64(SPACES_AT(off));
    off += length;
    //NEED_IN_WINDOW(off);
    
    cursor += off;
    
    /*
     * Check for errors
     */
    err |= (idx == 0);
    err |= (off == 0);
    err |= (off >= m.avail);
    uint64_t other = hdr_other_mask(&m);
    err |= (ctz64(other) < off);
    err |= (data[cursor] == '(');
    err |= (data[cursor] == ')');
    err |= (data[cursor] == ';');
    if (err)
        goto slow_path;
 
 
    uint8_t *dst = out->wire.buf + out->wire.len;
    store_be16(dst + 0, (uint16_t)rrtype);
    store_be16(dst + 2, (uint16_t)rrclass);
    store_be32(dst + 4, (uint32_t)rrttl);
    out->wire.len += 8;

    return cursor;

slow_path:
    return zone_parse_header(data, orig_cursor, max, out, depth);

#undef NEED_IN_WINDOW
#undef SPACES_AT
#undef ALNUM_AT
}
