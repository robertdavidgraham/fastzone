/* zone-parse-token.c
 *
 * Token/space scanning with persistent SIMD masks.
 *
 * We maintain a rolling classification window for the bytes starting at the
 * *current* cursor position:
 *   - tokens->mask_st : bit i == 1 iff byte i is ' ' or '\t'
 *   - tokens->mask_ws : bit i == 1 iff byte i is ' ', '\t', '\r', or '\n'
 *   - tokens->avail   : number of valid bits/bytes currently in the masks (<= 64)
 *
 * Public API (implement in a header if you want, but kept here as requested):
 *
 *   typedef struct parsetokens_t {
 *       uint64_t mask_st;
 *       uint64_t mask_ws;
 *       unsigned avail;
 *   } parsetokens_t;
 *
 *   void   parse_tokens_init(simd_backend_t backend);
 *   size_t parse_token_length(const char *data, size_t cursor, parsetokens_t *tokens);
 *   size_t parse_space_length(const char *data, size_t cursor, parsetokens_t *tokens);
 *   void   parse_token_consume(size_t length, parsetokens_t *tokens);
 *
 * Semantics:
 *   - tokens represents the state at (data + cursor) *after any prior consumption*.
 *   - parse_token_length consumes through the token (stops at first WS: ' ', '\t', '\r', '\n')
 *     and returns the token length.
 *   - parse_space_length consumes a run of only (' ' or '\t') and returns that length.
 *   - parse_token_consume lets you consume an arbitrary number of bytes from the
 *     current token window (without changing data/cursor), e.g. when you skip bytes
 *     for other reasons.
 *
 * Contract assumptions per your project style:
 *   - buffer is overread-safe (>=64 bytes) and terminates with newline.
 *   - no max checks here.
 *
 * Windows:
 *   - Works with MSVC/clang-cl; uses util-simd.h ctz32/ctz64 and simd_get_best().
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "util-simd.h"   /* ctz32(), ctz64(), simd_get_best(), simd_backend_t */

/* ----------------------------- State ----------------------------- */

typedef struct parsetokens_t {
    uint64_t mask_st; /* space/tab */
    uint64_t mask_ws; /* space/tab/cr/nl */
    unsigned avail;   /* 0..64 */
} parsetokens_t;

/* scanner fills tokens->mask_st/mask_ws and tokens->avail for bytes starting at p */
typedef void (*scan_tokens_fn)(const char *p, parsetokens_t *tokens);
static scan_tokens_fn scanner = 0;

/* -------------------------- Utilities --------------------------- */

static inline uint64_t avail_mask_u64(unsigned avail)
{
    if (avail >= 64) return ~0ULL;
    if (avail == 0)  return 0ULL;
    return (1ULL << avail) - 1ULL;
}

/* Consume n bytes from the current masks (n <= tokens->avail). */
void parse_token_consume(size_t length, parsetokens_t *tokens)
{
    size_t n = length;
    while (n) {
        unsigned a = tokens->avail;
        if (a == 0) {
            /* Caller should normally refill via parse_* calls which know the pointer.
               If you call consume directly with avail==0, it becomes a no-op. */
            return;
        }
        unsigned step = (n < (size_t)a) ? (unsigned)n : a;
        tokens->mask_st >>= step;
        tokens->mask_ws >>= step;
        tokens->avail    = a - step;
        if (tokens->avail == 0) {
            tokens->mask_st = 0;
            tokens->mask_ws = 0;
        }
        n -= step;
    }
}

static inline void ensure_refill(const char *p, parsetokens_t *tokens)
{
    if (tokens->avail == 0) {
        scanner(p, tokens);
        if (tokens->avail > 64) tokens->avail = 64;
        {
            const uint64_t am = avail_mask_u64(tokens->avail);
            tokens->mask_st &= am;
            tokens->mask_ws &= am;
        }
    } else {
        const uint64_t am = avail_mask_u64(tokens->avail);
        tokens->mask_st &= am;
        tokens->mask_ws &= am;
    }
}

/* ----------------------- Wrapper functions ---------------------- */

/* Returns length of token ended by ANY of: ' ', '\t', '\r', '\n'
 * Consumes that token in tokens-state.
 */
size_t parse_token_length2(const char *data, size_t cursor, parsetokens_t *tokens)
{
    size_t total = 0;

    for (;;) {
        ensure_refill(data + cursor + total, tokens);

        const uint64_t am = avail_mask_u64(tokens->avail);
        const uint64_t ws = tokens->mask_ws & am;

        if (ws) {
            const unsigned n = (unsigned)ctz64(ws);
            parse_token_consume((size_t)n, tokens);
            total += (size_t)n;
            return total;
        }

        /* No ws in this chunk: consume whole chunk and continue. */
        {
            const unsigned n = tokens->avail;
            parse_token_consume((size_t)n, tokens);
            total += (size_t)n;
        }
    }
}

/* Returns length of run of ONLY (' ' or '\t')
 * Consumes that run in tokens-state.
 */
size_t parse_space_length2(const char *data, size_t cursor, parsetokens_t *tokens)
{
    size_t total = 0;

    for (;;) {
        ensure_refill(data + cursor + total, tokens);

        const uint64_t am = avail_mask_u64(tokens->avail);
        const uint64_t st = tokens->mask_st & am;

        /* If first byte isn't space/tab, we're done. */
        if ((st & 1ULL) == 0) return total;

        /* Count consecutive 1 bits from LSB within avail. */
        const uint64_t non_st = (~st) & am;
        unsigned run;
        if (non_st == 0) {
            run = tokens->avail; /* entire chunk is space/tab */
        } else {
            run = (unsigned)ctz64(non_st);
        }

        parse_token_consume((size_t)run, tokens);
        total += (size_t)run;

        /* If we didn't consume whole chunk, next is non-st -> done. */
        if (tokens->avail != 0) return total;

        /* else avail==0 => refill next iteration */
    }
}

/* -------------------------- Backends ---------------------------- */

static inline uint64_t build_mask_st_scalar(const uint8_t *s, unsigned n)
{
    uint64_t m = 0;
    for (unsigned i = 0; i < n; i++) {
        const uint8_t c = s[i];
        const uint64_t isst = (uint64_t)((c == (uint8_t)' ') | (c == (uint8_t)'\t'));
        m |= (isst << i);
    }
    return m;
}

static inline uint64_t build_mask_ws_scalar(const uint8_t *s, unsigned n)
{
    uint64_t m = 0;
    for (unsigned i = 0; i < n; i++) {
        const uint8_t c = s[i];
        const uint64_t isws = (uint64_t)((c == (uint8_t)' ') | (c == (uint8_t)'\t') |
                                         (c == (uint8_t)'\r') | (c == (uint8_t)'\n'));
        m |= (isws << i);
    }
    return m;
}

static void scan_scalar(const char *p, parsetokens_t *t)
{
    const uint8_t *s = (const uint8_t *)(const void *)p;
    const unsigned n = 16; /* scalar refill size; 16 is a decent compromise */
    t->avail   = n;
    t->mask_st = build_mask_st_scalar(s, n);
    t->mask_ws = build_mask_ws_scalar(s, n);
}

/* Explicit SWAR scanner (different from scalar):
 * - Processes 32 bytes per refill (four 8-byte words).
 * - Uses classic SWAR "has_byte_eq" trick to find matches for each of:
 *     ' ' , '\t' , '\r' , '\n'
 * - Builds two masks:
 *     mask_st: space/tab
 *     mask_ws: space/tab/cr/nl
 * - Each mask bit i corresponds to byte i in the 32-byte window.
 *
 * Drop this in place of the old scan_swar() in zone-parse-token.c
 */

static inline uint64_t swar_has_byte_eq64(uint64_t x, uint64_t byte_repeat)
{
    /* Returns a word where each matching byte has its high bit set (0x80),
       non-matching bytes have 0x00 in their high bit.
       (x ^ byte_repeat) == 0 in matching bytes.
       The classic zero-byte test: ((y - 0x01..01) & ~y & 0x80..80)
    */
    uint64_t y = x ^ byte_repeat;
    return (y - 0x0101010101010101ULL) & (~y) & 0x8080808080808080ULL;
}

static inline uint32_t swar_mask8_from_highbits(uint64_t hb)
{
    /* Convert 0x8080.. style byte-highbit markers into an 8-bit mask. */
#if defined(_MSC_VER) && defined(_M_X64)
    /* MSVC x64 has _pext_u64 */
    return (uint32_t)_pext_u64(hb, 0x8080808080808080ULL);
#else
    /* Portable bit-gather: multiply and shift.
       After this: bit7 of each byte becomes bit (0..7) of result.
     */
    return (uint32_t)((hb * 0x02040810204081ULL) >> 56);
#endif
}

static inline uint64_t swar_repeat_u8(uint8_t c)
{
    return 0x0101010101010101ULL * (uint64_t)c;
}

static void scan_swar(const char *p, parsetokens_t *t)
{
    const uint8_t *s = (const uint8_t *)(const void *)p;

    /* Load 4x u64 = 32 bytes. Unaligned loads are OK. */
    uint64_t w0, w1, w2, w3;
    memcpy(&w0, s +  0, 8);
    memcpy(&w1, s +  8, 8);
    memcpy(&w2, s + 16, 8);
    memcpy(&w3, s + 24, 8);

    const uint64_t r_sp = swar_repeat_u8((uint8_t)' ');
    const uint64_t r_tb = swar_repeat_u8((uint8_t)'\t');
    const uint64_t r_cr = swar_repeat_u8((uint8_t)'\r');
    const uint64_t r_nl = swar_repeat_u8((uint8_t)'\n');

    /* For each 8-byte word, compute which bytes match each target.
       swar_has_byte_eq64 returns 0x80 in the matching bytes.
     */
    const uint64_t hb_sp0 = swar_has_byte_eq64(w0, r_sp);
    const uint64_t hb_sp1 = swar_has_byte_eq64(w1, r_sp);
    const uint64_t hb_sp2 = swar_has_byte_eq64(w2, r_sp);
    const uint64_t hb_sp3 = swar_has_byte_eq64(w3, r_sp);

    const uint64_t hb_tb0 = swar_has_byte_eq64(w0, r_tb);
    const uint64_t hb_tb1 = swar_has_byte_eq64(w1, r_tb);
    const uint64_t hb_tb2 = swar_has_byte_eq64(w2, r_tb);
    const uint64_t hb_tb3 = swar_has_byte_eq64(w3, r_tb);

    const uint64_t hb_cr0 = swar_has_byte_eq64(w0, r_cr);
    const uint64_t hb_cr1 = swar_has_byte_eq64(w1, r_cr);
    const uint64_t hb_cr2 = swar_has_byte_eq64(w2, r_cr);
    const uint64_t hb_cr3 = swar_has_byte_eq64(w3, r_cr);

    const uint64_t hb_nl0 = swar_has_byte_eq64(w0, r_nl);
    const uint64_t hb_nl1 = swar_has_byte_eq64(w1, r_nl);
    const uint64_t hb_nl2 = swar_has_byte_eq64(w2, r_nl);
    const uint64_t hb_nl3 = swar_has_byte_eq64(w3, r_nl);

    /* Collapse each 8-byte chunk to 8-bit masks. */
    const uint32_t m_sp0 = swar_mask8_from_highbits(hb_sp0);
    const uint32_t m_sp1 = swar_mask8_from_highbits(hb_sp1);
    const uint32_t m_sp2 = swar_mask8_from_highbits(hb_sp2);
    const uint32_t m_sp3 = swar_mask8_from_highbits(hb_sp3);

    const uint32_t m_tb0 = swar_mask8_from_highbits(hb_tb0);
    const uint32_t m_tb1 = swar_mask8_from_highbits(hb_tb1);
    const uint32_t m_tb2 = swar_mask8_from_highbits(hb_tb2);
    const uint32_t m_tb3 = swar_mask8_from_highbits(hb_tb3);

    const uint32_t m_cr0 = swar_mask8_from_highbits(hb_cr0);
    const uint32_t m_cr1 = swar_mask8_from_highbits(hb_cr1);
    const uint32_t m_cr2 = swar_mask8_from_highbits(hb_cr2);
    const uint32_t m_cr3 = swar_mask8_from_highbits(hb_cr3);

    const uint32_t m_nl0 = swar_mask8_from_highbits(hb_nl0);
    const uint32_t m_nl1 = swar_mask8_from_highbits(hb_nl1);
    const uint32_t m_nl2 = swar_mask8_from_highbits(hb_nl2);
    const uint32_t m_nl3 = swar_mask8_from_highbits(hb_nl3);

    /* Assemble final 32-bit masks (bit i corresponds to byte i). */
    const uint32_t st =
        (m_sp0 | m_tb0) |
        ((m_sp1 | m_tb1) << 8) |
        ((m_sp2 | m_tb2) << 16) |
        ((m_sp3 | m_tb3) << 24);

    const uint32_t ws =
        (m_sp0 | m_tb0 | m_cr0 | m_nl0) |
        ((m_sp1 | m_tb1 | m_cr1 | m_nl1) << 8) |
        ((m_sp2 | m_tb2 | m_cr2 | m_nl2) << 16) |
        ((m_sp3 | m_tb3 | m_cr3 | m_nl3) << 24);

    t->avail   = 32;
    t->mask_st = (uint64_t)st;
    t->mask_ws = (uint64_t)ws;
}

#if defined(SIMD_SSE2) || defined(SIMD_SSE42)
#include <immintrin.h>

static void scan_sse2_impl(const char *p, parsetokens_t *t)
{
    const __m128i v  = _mm_loadu_si128((const __m128i *)(const void *)p);
    const __m128i sp = _mm_set1_epi8(' ');
    const __m128i tb = _mm_set1_epi8('\t');
    const __m128i cr = _mm_set1_epi8('\r');
    const __m128i nl = _mm_set1_epi8('\n');

    __m128i m_st = _mm_or_si128(_mm_cmpeq_epi8(v, sp), _mm_cmpeq_epi8(v, tb));
    __m128i m_ws = _mm_or_si128(m_st, _mm_or_si128(_mm_cmpeq_epi8(v, cr), _mm_cmpeq_epi8(v, nl)));

    t->avail   = 16;
    t->mask_st = (uint64_t)(uint32_t)_mm_movemask_epi8(m_st);
    t->mask_ws = (uint64_t)(uint32_t)_mm_movemask_epi8(m_ws);
}

static void scan_sse2 (const char *p, parsetokens_t *t) { scan_sse2_impl(p, t); }
static void scan_sse42(const char *p, parsetokens_t *t) { scan_sse2_impl(p, t); }
#endif

#if defined(SIMD_AVX2)
#include <immintrin.h>

static void scan_avx2(const char *p, parsetokens_t *t)
{
    const __m256i v  = _mm256_loadu_si256((const __m256i *)(const void *)p);
    const __m256i sp = _mm256_set1_epi8(' ');
    const __m256i tb = _mm256_set1_epi8('\t');
    const __m256i cr = _mm256_set1_epi8('\r');
    const __m256i nl = _mm256_set1_epi8('\n');

    __m256i m_st = _mm256_or_si256(_mm256_cmpeq_epi8(v, sp), _mm256_cmpeq_epi8(v, tb));
    __m256i m_ws = _mm256_or_si256(m_st,
                    _mm256_or_si256(_mm256_cmpeq_epi8(v, cr), _mm256_cmpeq_epi8(v, nl)));

    t->avail   = 32;
    t->mask_st = (uint64_t)(uint32_t)_mm256_movemask_epi8(m_st);
    t->mask_ws = (uint64_t)(uint32_t)_mm256_movemask_epi8(m_ws);
}
#endif

#if defined(SIMD_AVX512)
#include <immintrin.h>

static void scan_avx512(const char *p, parsetokens_t *t)
{
    const __m512i v  = _mm512_loadu_si512((const void *)p);
    const __m512i sp = _mm512_set1_epi8(' ');
    const __m512i tb = _mm512_set1_epi8('\t');
    const __m512i cr = _mm512_set1_epi8('\r');
    const __m512i nl = _mm512_set1_epi8('\n');

    const __mmask64 m_st = _mm512_cmpeq_epi8_mask(v, sp) | _mm512_cmpeq_epi8_mask(v, tb);
    const __mmask64 m_ws = m_st | _mm512_cmpeq_epi8_mask(v, cr) | _mm512_cmpeq_epi8_mask(v, nl);

    t->avail   = 64;
    t->mask_st = (uint64_t)m_st;
    t->mask_ws = (uint64_t)m_ws;
}
#endif

#if defined(SIMD_NEON)
#include <arm_neon.h>

static inline uint32_t neon_movemask_u8(uint8x16_t vff00)
{
    uint8x16_t b = vshrq_n_u8(vff00, 7);
    const int8x8_t shifts = (int8x8_t){0,1,2,3,4,5,6,7};
    uint8x8_t lo = vshl_u8(vget_low_u8(b), shifts);
    uint8x8_t hi = vshl_u8(vget_high_u8(b), shifts);
    return (uint32_t)vaddv_u8(lo) | ((uint32_t)vaddv_u8(hi) << 8);
}

static void scan_neon(const char *p, parsetokens_t *t)
{
    const uint8x16_t sp = vdupq_n_u8((uint8_t)' ');
    const uint8x16_t tb = vdupq_n_u8((uint8_t)'\t');
    const uint8x16_t cr = vdupq_n_u8((uint8_t)'\r');
    const uint8x16_t nl = vdupq_n_u8((uint8_t)'\n');

    uint64_t mask_st = 0;
    uint64_t mask_ws = 0;
    unsigned i;

    for (i = 0; i < 4; i++) {
        const uint8x16_t v = vld1q_u8((const uint8_t *)(const void *)(p + i * 16));

        uint8x16_t st = vorrq_u8(vceqq_u8(v, sp), vceqq_u8(v, tb));
        uint8x16_t ws = vorrq_u8(st, vorrq_u8(vceqq_u8(v, cr), vceqq_u8(v, nl)));

        mask_st |= (uint64_t)neon_movemask_u8(st) << (i * 16);
        mask_ws |= (uint64_t)neon_movemask_u8(ws) << (i * 16);
    }

    t->avail   = 64;
    t->mask_st = mask_st;
    t->mask_ws = mask_ws;
}
#endif

#if defined(SIMD_SVE2)
#include <arm_sve.h>

/* Pack <=64 lanes worth of (0xFF/0x00) bytes into uint64 bitmask. */
static inline uint64_t pack_ff00_to_u64(const uint8_t *tmp, size_t n)
{
    uint64_t m = 0;
    for (size_t i = 0; i < n; i++) {
        m |= ((uint64_t)(tmp[i] >> 7) << i);
    }
    return m;
}

static void scan_sve2(const char *p, parsetokens_t *t)
{
    size_t vl = svcntb();
    if (vl > 64) vl = 64;

    svbool_t pg = svwhilelt_b8((uint64_t)0, (uint64_t)vl);
    svuint8_t v = svld1_u8(pg, (const uint8_t *)(const void *)p);

    svbool_t m_sp = svcmpeq_u8(pg, v, svdup_u8((uint8_t)' '));
    svbool_t m_tb = svcmpeq_u8(pg, v, svdup_u8((uint8_t)'\t'));
    svbool_t m_cr = svcmpeq_u8(pg, v, svdup_u8((uint8_t)'\r'));
    svbool_t m_nl = svcmpeq_u8(pg, v, svdup_u8((uint8_t)'\n'));

    svbool_t m_st = svorr_b_z(pg, m_sp, m_tb);
    svbool_t m_ws = svorr_b_z(pg, m_st, svorr_b_z(pg, m_cr, m_nl));

    /* Materialize predicate to bytes then pack. */
    uint8_t tmp_st[64];
    uint8_t tmp_ws[64];

    svuint8_t b_st = svsel_u8(pg, m_st, svdup_u8(0xFF), svdup_u8(0x00));
    svuint8_t b_ws = svsel_u8(pg, m_ws, svdup_u8(0xFF), svdup_u8(0x00));

    svst1_u8(pg, tmp_st, b_st);
    svst1_u8(pg, tmp_ws, b_ws);

    t->avail   = (unsigned)vl;
    t->mask_st = pack_ff00_to_u64(tmp_st, vl);
    t->mask_ws = pack_ff00_to_u64(tmp_ws, vl);
}
#endif

#if defined(SIMD_RISCVV)
#include <riscv_vector.h>

static inline uint64_t pack_ff00_to_u64_rvv(const uint8_t *tmp, size_t n)
{
    uint64_t m = 0;
    for (size_t i = 0; i < n; i++) {
        m |= ((uint64_t)(tmp[i] >> 7) << i);
    }
    return m;
}

static void scan_riscvv(const char *p, parsetokens_t *t)
{
    const uint8_t *s = (const uint8_t *)(const void *)p;

    /* Refill up to 64 bytes (fits in uint64 masks). */
    size_t vl = vsetvl_e8m1((size_t)64);

    vuint8m1_t v = vle8_v_u8m1(s, vl);

    vbool8_t m_sp = vmseq_vx_u8m1_b8(v, (uint8_t)' ',  vl);
    vbool8_t m_tb = vmseq_vx_u8m1_b8(v, (uint8_t)'\t', vl);
    vbool8_t m_cr = vmseq_vx_u8m1_b8(v, (uint8_t)'\r', vl);
    vbool8_t m_nl = vmseq_vx_u8m1_b8(v, (uint8_t)'\n', vl);

    vbool8_t m_st = vmor_mm_b8(m_sp, m_tb, vl);
    vbool8_t m_ws = vmor_mm_b8(m_st, vmor_mm_b8(m_cr, m_nl, vl), vl);

    /* Materialize to bytes and pack. */
    vuint8m1_t z = vmv_v_x_u8m1(0x00, vl);
    vuint8m1_t o = vmv_v_x_u8m1(0xFF, vl);

    vuint8m1_t b_st = vmerge_vvm_u8m1(z, o, m_st, vl);
    vuint8m1_t b_ws = vmerge_vvm_u8m1(z, o, m_ws, vl);

    uint8_t tmp_st[64];
    uint8_t tmp_ws[64];

    vse8_v_u8m1(tmp_st, b_st, vl);
    vse8_v_u8m1(tmp_ws, b_ws, vl);

    t->avail   = (unsigned)vl;
    t->mask_st = pack_ff00_to_u64_rvv(tmp_st, vl);
    t->mask_ws = pack_ff00_to_u64_rvv(tmp_ws, vl);
}
#endif

/* ------------------------- Runtime init ------------------------- */

void parse_tokens_init(simd_backend_t backend)
{
    switch (backend) {
    case SIMD_AUTO:
        parse_tokens_init(simd_get_best());
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

    if (!scanner) scanner = scan_scalar;
}

/* ---------------------- Optional convenience -------------------- */
/* If you like, you can expose this helper in your header style: */
static inline void parse_tokens_reset(parsetokens_t *t)
{
    t->mask_st = 0;
    t->mask_ws = 0;
    t->avail   = 0;
}
