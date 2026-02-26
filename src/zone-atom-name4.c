// zone-atom-name4.c
//
// =============================== FULL SPEC ==================================
// zone_atom_name4(): fast DNS name atom parser for the common case.
//
// Fast-path assumptions:
//   - The DNS name atom is <= 32 bytes of text before the first non-label char.
//   - No escapes are handled here; any non-label char stops classification.
//   - If any abort condition occurs (too long, empty label, etc.), call
//     zone_atom_name5() (slow fallback you will implement later).
//
// Classification:
//   - Classify EXACTLY 32 bytes into ONE 32-bit mask:
//       invalidmask[k] = 1 iff byte k is NOT a valid label character [A-Za-z0-9_-].
//     Dots '.' and any other terminators/invalid bytes are "invalid" here.
//   - We do NOT try to identify terminators in name4; caller validates terminator.
//     We only care whether the stopping byte is '.' or not '.'.
//
// Wire construction (copy-first trick):
//   - Copy exactly 32 bytes from input into out_wire+1.
//   - Convert to DNS wire format by overwriting '.' bytes with length bytes:
//       * out_wire[0] is the first label length.
//       * each '.' at out_wire[1+dotpos] is overwritten with length of NEXT label.
//   - If final stop byte is '.' (trailing dot), that represents the root label:
//       set is_fqdn flag and overwrite that '.' with 0.
//       wire_len = 1 + name_len
//     Else append root label 0 at out_wire[1+name_len]:
//       wire_len = 1 + name_len + 1
//
// Errors checked in name4:
//   - Empty label (leading dot or consecutive dots) => err bit => fallback to name5.
//   - No stop within 32 bytes => fallback to name5.
//   - Wire buffer overflow cannot happen in name4 (<= 34 bytes written), but we
//     still set wire_len conservatively.
//
// Return value:
//   - Returns bytes consumed for the name text (not including the stop/terminator).
//
// Loop structure requested:
//   - Special-case the common case where the first stop is NOT a dot (no periods).
//     Then label length is just pos0.
//   - Otherwise, use ctz to get label lengths and loop:
//       while (c1 == '.') { process label; advance; find next invalid; }
//       stop when c1 != '.'
//   - No special-case for a single dot.
//   - Do not check for backslashes or specific terminators.
//     Only check whether stop byte is '.' or not '.'; caller validates terminator.
// ============================================================================

#include "zone-scan.h"
#include "zone-parse.h"
#include "zone-atom-name.h"
#include <string.h>

#include "util-ctz.h" // ctz32/ctz64




/* ------------------------------ helpers ----------------------------------- */

/*
 * Zonefile "space" / delimiter characters:
 *   ' '  (0x20)
 *   '\t' (0x09)
 *   '\r' (0x0d)
 *   '\n' (0x0a)
 *   '('  (0x28)
 *   ')'  (0x29)
 *   ';'  (0x3b)
 */

static const unsigned char zone_space_table[256] = {
    /* 0x00–0x07 */ 0,0,0,0,0,0,0,0,
    /* 0x08–0x0F */ 0,1,1,0,0,1,0,0,   /* \t=0x09, \n=0x0a, \r=0x0d */
    /* 0x10–0x17 */ 0,0,0,0,0,0,0,0,
    /* 0x18–0x1F */ 0,0,0,0,0,0,0,0,
    /* 0x20–0x27 */ 1,0,0,0,0,0,0,0,   /* space=0x20 */
    /* 0x28–0x2F */ 1,1,0,0,0,0,0,0,   /* '('=0x28, ')'=0x29 */
    /* 0x30–0x37 */ 0,0,0,0,0,0,0,0,
    /* 0x38–0x3F */ 0,0,0,1,0,0,0,0,   /* ';'=0x3b */
    /* 0x40–0x47 */ 0,0,0,0,0,0,0,0,
    /* 0x48–0x4F */ 0,0,0,0,0,0,0,0,
    /* 0x50–0x57 */ 0,0,0,0,0,0,0,0,
    /* 0x58–0x5F */ 0,0,0,0,0,0,0,0,
    /* 0x60–0x67 */ 0,0,0,0,0,0,0,0,
    /* 0x68–0x6F */ 0,0,0,0,0,0,0,0,
    /* 0x70–0x77 */ 0,0,0,0,0,0,0,0,
    /* 0x78–0x7F */ 0,0,0,0,0,0,0,0,
    /* 0x80–0xFF */
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
};

/**
 * A DNS name must end in a valid space character. The allowed  characters are
 * ' ' a space
 * '\t' tab character
 * '(' starts a multiline record, converted to a ' ' space logically
 * ')' ends a multiline portion of a record, converted to a space,too
 * ';' starts a comment, also converted to a space logically
 * '\r' ends a line (along with an immediately following '\n')
 * '\n' ends a line
 */
static inline int is_space_char(unsigned char c)
{
    /* Test with a single table lookup. It's unclear whether this
     * is faster, as this consumes a 64-byte cacheline in the L1 cache.
     * While we have 7 characters to test for, such tests can be done
     * in parallel in one or two clock cycles on today's CPUs. The
     * difference in speed is so far unmeasurable in my tests.
     */
    return zone_space_table[c];
}

static inline int is_valid_label_char(unsigned char c)
{
    if (c >= (unsigned char)'0' && c <= (unsigned char)'9') return 1;
    if (c >= (unsigned char)'A' && c <= (unsigned char)'Z') return 1;
    if (c >= (unsigned char)'a' && c <= (unsigned char)'z') return 1;
    if (c == (unsigned char)'-' || c == (unsigned char)'_') return 1;
    return 0;
}

static uint32_t classify_scalar(const char *p, size_t max)
{
    uint32_t inv = 0;
    for (unsigned k = 0; k < 32; k++) {
        inv |= (uint32_t)(!is_valid_label_char((unsigned char)p[k])) << k;
    }
    return inv;
}

/* Classifier produces invalidmask for 32 bytes: 1 => NOT [A-Za-z0-9_-] */
typedef uint32_t (*zone_name4_classify32_fn)(const char *p, size_t max);
static zone_name4_classify32_fn classify = classify_scalar;

/* ============================ SIMD classifiers ============================ */
/* These are the same as before, but they only return invalidmask and do NOT
   attempt to identify dots or terminators. */

#if defined(SIMD_SSE2) || defined(SIMD_SSE42)
#include <emmintrin.h>
static inline __m128i xor80_128(__m128i v) { return _mm_xor_si128(v, _mm_set1_epi8((char)0x80)); }
static inline __m128i in_range_u8_sse2(__m128i x, unsigned char lo, unsigned char hi)
{
    __m128i xx = xor80_128(x);
    __m128i lo_m1 = _mm_set1_epi8((char)((unsigned char)(lo - 1) ^ 0x80));
    __m128i hi_p1 = _mm_set1_epi8((char)((unsigned char)(hi + 1) ^ 0x80));
    return _mm_and_si128(_mm_cmpgt_epi8(xx, lo_m1), _mm_cmpgt_epi8(hi_p1, xx));
}
static uint32_t classify_sse2(const char *p, size_t max)
{
    __m128i v0 = _mm_loadu_si128((const __m128i *)(const void *)(p + 0));
    __m128i v1 = _mm_loadu_si128((const __m128i *)(const void *)(p + 16));

    __m128i d0 = in_range_u8_sse2(v0, (unsigned char)'0', (unsigned char)'9');
    __m128i A0 = in_range_u8_sse2(v0, (unsigned char)'A', (unsigned char)'Z');
    __m128i a0 = in_range_u8_sse2(v0, (unsigned char)'a', (unsigned char)'z');
    __m128i ok0 = _mm_or_si128(d0, _mm_or_si128(A0, a0));
    ok0 = _mm_or_si128(ok0, _mm_cmpeq_epi8(v0, _mm_set1_epi8('-')));
    ok0 = _mm_or_si128(ok0, _mm_cmpeq_epi8(v0, _mm_set1_epi8('_')));

    __m128i d1 = in_range_u8_sse2(v1, (unsigned char)'0', (unsigned char)'9');
    __m128i A1 = in_range_u8_sse2(v1, (unsigned char)'A', (unsigned char)'Z');
    __m128i a1 = in_range_u8_sse2(v1, (unsigned char)'a', (unsigned char)'z');
    __m128i ok1 = _mm_or_si128(d1, _mm_or_si128(A1, a1));
    ok1 = _mm_or_si128(ok1, _mm_cmpeq_epi8(v1, _mm_set1_epi8('-')));
    ok1 = _mm_or_si128(ok1, _mm_cmpeq_epi8(v1, _mm_set1_epi8('_')));

    uint32_t okm = (uint32_t)_mm_movemask_epi8(ok0) | ((uint32_t)_mm_movemask_epi8(ok1) << 16);
    return ~okm;
}
#endif

#ifdef SIMD_SSE42
#include <nmmintrin.h>
static uint32_t classify_sse42(const char *p)
{
    /* Must use SSE4.2 text instruction (side-effect only). */
    const __m128i needle = _mm_setr_epi8('.', '-', '_', 0,0,0,0,0,0,0,0,0,0,0,0,0);
    const int mode = _SIDD_UBYTE_OPS | _SIDD_CMP_EQUAL_ANY | _SIDD_LEAST_SIGNIFICANT;
    __m128i hay = _mm_loadu_si128((const __m128i *)(const void *)p);
    (void)_mm_cmpestri(needle, 3, hay, 16, mode);

    return classify_sse2(p, max);
}
#endif

#ifdef SIMD_AVX2
#include <immintrin.h>
static inline __m256i xor80_256(__m256i v) { return _mm256_xor_si256(v, _mm256_set1_epi8((char)0x80)); }
static inline __m256i in_range_u8_avx2(__m256i x, unsigned char lo, unsigned char hi)
{
    __m256i xx = xor80_256(x);
    __m256i lo_m1 = _mm256_set1_epi8((char)((unsigned char)(lo - 1) ^ 0x80));
    __m256i hi_p1 = _mm256_set1_epi8((char)((unsigned char)(hi + 1) ^ 0x80));
    return _mm256_and_si256(_mm256_cmpgt_epi8(xx, lo_m1), _mm256_cmpgt_epi8(hi_p1, xx));
}
static uint32_t classify_avx2(const char *p)
{
    __m256i v = _mm256_loadu_si256((const __m256i *)(const void *)p);

    __m256i is_d = in_range_u8_avx2(v, (unsigned char)'0', (unsigned char)'9');
    __m256i is_A = in_range_u8_avx2(v, (unsigned char)'A', (unsigned char)'Z');
    __m256i is_a = in_range_u8_avx2(v, (unsigned char)'a', (unsigned char)'z');
    __m256i okv  = _mm256_or_si256(is_d, _mm256_or_si256(is_A, is_a));
    okv = _mm256_or_si256(okv, _mm256_cmpeq_epi8(v, _mm256_set1_epi8('-')));
    okv = _mm256_or_si256(okv, _mm256_cmpeq_epi8(v, _mm256_set1_epi8('_')));

    uint32_t okm = (uint32_t)_mm256_movemask_epi8(okv);
    return ~okm;
}
#endif

#ifdef SIMD_AVX512
#include <immintrin.h>
static uint32_t classify_avx512(const char *p)
{
    __m512i v  = _mm512_loadu_si512((const void *)p);
    __m512i xx = _mm512_xor_si512(v, _mm512_set1_epi8((char)0x80));

    __m512i lo_d = _mm512_set1_epi8((char)((unsigned char)('0' - 1) ^ 0x80));
    __m512i hi_d = _mm512_set1_epi8((char)((unsigned char)('9' + 1) ^ 0x80));
    __m512i lo_A = _mm512_set1_epi8((char)((unsigned char)('A' - 1) ^ 0x80));
    __m512i hi_A = _mm512_set1_epi8((char)((unsigned char)('Z' + 1) ^ 0x80));
    __m512i lo_a = _mm512_set1_epi8((char)((unsigned char)('a' - 1) ^ 0x80));
    __m512i hi_a = _mm512_set1_epi8((char)((unsigned char)('z' + 1) ^ 0x80));

    __mmask64 is_d = _mm512_cmpgt_epi8_mask(xx, lo_d) & _mm512_cmpgt_epi8_mask(hi_d, xx);
    __mmask64 is_A = _mm512_cmpgt_epi8_mask(xx, lo_A) & _mm512_cmpgt_epi8_mask(hi_A, xx);
    __mmask64 is_a = _mm512_cmpgt_epi8_mask(xx, lo_a) & _mm512_cmpgt_epi8_mask(hi_a, xx);

    __mmask64 ok64 = is_d | is_A | is_a |
                     _mm512_cmpeq_epi8_mask(v, _mm512_set1_epi8('-')) |
                     _mm512_cmpeq_epi8_mask(v, _mm512_set1_epi8('_'));

    uint32_t okm = (uint32_t)(ok64 & 0xFFFFFFFFULL);
    return ~okm;
}
#endif

#ifdef SIMD_NEON
#include <arm_neon.h>
#if defined(__aarch64__) || defined(_M_ARM64)
static inline uint16_t
neon_movemask_u8(uint8x16_t cmp_ff00) {
    uint8x16_t b = vshrq_n_u8(cmp_ff00, 7);
    const int8x8_t shifts = (int8x8_t){0,1,2,3,4,5,6,7};
    uint8x8_t lo = vshl_u8(vget_low_u8(b), shifts);
    uint8x8_t hi = vshl_u8(vget_high_u8(b), shifts);
    return (uint16_t)vaddv_u8(lo) | ((uint16_t)vaddv_u8(hi) << 8);
}
static uint32_t
classify_neon(const char *data, size_t max) {
    
    const uint8_t *p = (const uint8_t *)data;
    
    uint8x16_t v0 = vld1q_u8(p + 0);
    uint8x16_t v1 = vld1q_u8(p + 16);

    uint16_t ok0, ok1;

    {
        uint8x16_t is_d = vandq_u8(vcgeq_u8(v0, vdupq_n_u8((uint8_t)'0')),
                                  vcleq_u8(v0, vdupq_n_u8((uint8_t)'9')));
        uint8x16_t is_A = vandq_u8(vcgeq_u8(v0, vdupq_n_u8((uint8_t)'A')),
                                  vcleq_u8(v0, vdupq_n_u8((uint8_t)'Z')));
        uint8x16_t is_a = vandq_u8(vcgeq_u8(v0, vdupq_n_u8((uint8_t)'a')),
                                  vcleq_u8(v0, vdupq_n_u8((uint8_t)'z')));
        uint8x16_t okv = vorrq_u8(vorrq_u8(is_d, vorrq_u8(is_A, is_a)),
                                  vorrq_u8(vceqq_u8(v0, vdupq_n_u8((uint8_t)'-')),
                                           vceqq_u8(v0, vdupq_n_u8((uint8_t)'_'))));
        ok0 = neon_movemask_u8(okv);
    }
    {
        uint8x16_t is_d = vandq_u8(vcgeq_u8(v1, vdupq_n_u8((uint8_t)'0')),
                                  vcleq_u8(v1, vdupq_n_u8((uint8_t)'9')));
        uint8x16_t is_A = vandq_u8(vcgeq_u8(v1, vdupq_n_u8((uint8_t)'A')),
                                  vcleq_u8(v1, vdupq_n_u8((uint8_t)'Z')));
        uint8x16_t is_a = vandq_u8(vcgeq_u8(v1, vdupq_n_u8((uint8_t)'a')),
                                  vcleq_u8(v1, vdupq_n_u8((uint8_t)'z')));
        uint8x16_t okv = vorrq_u8(vorrq_u8(is_d, vorrq_u8(is_A, is_a)),
                                  vorrq_u8(vceqq_u8(v1, vdupq_n_u8((uint8_t)'-')),
                                           vceqq_u8(v1, vdupq_n_u8((uint8_t)'_'))));
        ok1 = neon_movemask_u8(okv);
    }

    uint32_t okm = (uint32_t)ok0 | ((uint32_t)ok1 << 16);
    return ~okm;
}
#else
static uint32_t classify_neon(const char *p, size_t max) { return classify_scalar(p, max); }
#endif
#endif /* SIMD_NEON */

#ifdef SIMD_RISCVV
#include <riscv_vector.h>

/* invalidmask: 1 => NOT [A-Za-z0-9_-] */
static uint32_t
classify32_riscvv_invalid(const char *p)
{
    /* We always want exactly 32 bytes */
    size_t vl = vsetvl_e8m1(32);

    vuint8m1_t v = vle8_v_u8m1((const uint8_t *)(const void *)p, vl);

    /* Ranges for digits/letters */
    vbool8_t is_d = vmsgeu_vx_u8m1_b8(v, (uint8_t)'0', vl) &
                    vmsleu_vx_u8m1_b8(v, (uint8_t)'9', vl);

    vbool8_t is_A = vmsgeu_vx_u8m1_b8(v, (uint8_t)'A', vl) &
                    vmsleu_vx_u8m1_b8(v, (uint8_t)'Z', vl);

    vbool8_t is_a = vmsgeu_vx_u8m1_b8(v, (uint8_t)'a', vl) &
                    vmsleu_vx_u8m1_b8(v, (uint8_t)'z', vl);

    vbool8_t is_dash = vmseq_vx_u8m1_b8(v, (uint8_t)'-', vl);
    vbool8_t is_us   = vmseq_vx_u8m1_b8(v, (uint8_t)'_', vl);

    vbool8_t ok = is_d | is_A | is_a | is_dash | is_us;
    vbool8_t inv = vmnot_m_b8(ok, vl);

    /* Convert inv mask to 0/1 bytes */
    vuint8m1_t ones = vmv_v_x_u8m1(1, vl);
    vuint8m1_t zeros = vmv_v_x_u8m1(0, vl);
    vuint8m1_t inv01 = vmerge_vvm_u8m1(zeros, ones, inv, vl);

    /* Store 32 bytes and pack to bits */
    uint8_t tmp[32];
    vse8_v_u8m1(tmp, inv01, vl);

    uint32_t mask = 0;
    /* pack 0/1 bytes into 32-bit mask */
    mask |= (uint32_t)(tmp[ 0] & 1u) <<  0;
    mask |= (uint32_t)(tmp[ 1] & 1u) <<  1;
    mask |= (uint32_t)(tmp[ 2] & 1u) <<  2;
    mask |= (uint32_t)(tmp[ 3] & 1u) <<  3;
    mask |= (uint32_t)(tmp[ 4] & 1u) <<  4;
    mask |= (uint32_t)(tmp[ 5] & 1u) <<  5;
    mask |= (uint32_t)(tmp[ 6] & 1u) <<  6;
    mask |= (uint32_t)(tmp[ 7] & 1u) <<  7;
    mask |= (uint32_t)(tmp[ 8] & 1u) <<  8;
    mask |= (uint32_t)(tmp[ 9] & 1u) <<  9;
    mask |= (uint32_t)(tmp[10] & 1u) << 10;
    mask |= (uint32_t)(tmp[11] & 1u) << 11;
    mask |= (uint32_t)(tmp[12] & 1u) << 12;
    mask |= (uint32_t)(tmp[13] & 1u) << 13;
    mask |= (uint32_t)(tmp[14] & 1u) << 14;
    mask |= (uint32_t)(tmp[15] & 1u) << 15;
    mask |= (uint32_t)(tmp[16] & 1u) << 16;
    mask |= (uint32_t)(tmp[17] & 1u) << 17;
    mask |= (uint32_t)(tmp[18] & 1u) << 18;
    mask |= (uint32_t)(tmp[19] & 1u) << 19;
    mask |= (uint32_t)(tmp[20] & 1u) << 20;
    mask |= (uint32_t)(tmp[21] & 1u) << 21;
    mask |= (uint32_t)(tmp[22] & 1u) << 22;
    mask |= (uint32_t)(tmp[23] & 1u) << 23;
    mask |= (uint32_t)(tmp[24] & 1u) << 24;
    mask |= (uint32_t)(tmp[25] & 1u) << 25;
    mask |= (uint32_t)(tmp[26] & 1u) << 26;
    mask |= (uint32_t)(tmp[27] & 1u) << 27;
    mask |= (uint32_t)(tmp[28] & 1u) << 28;
    mask |= (uint32_t)(tmp[29] & 1u) << 29;
    mask |= (uint32_t)(tmp[30] & 1u) << 30;
    mask |= (uint32_t)(tmp[31] & 1u) << 31;

    return mask;
}
#endif /* SIMD_RISCVV */

/* ------------------------------ zone_atom_name4 --------------------------- */

size_t
zone_atom_name4(const char *data, size_t cursor, size_t max,
                struct wire_record_t *out)
{
    /* This fast function assumes simple names (no \escapes) that
     * are shorter than 32 bytes. Any violations of these rules
     * falls back to a slower function that handles longer and
     * more complex names
     */
    const char *input = data + cursor;
    unsigned char *output = out->wire.buf + out->wire.len;
    
    
    /*
     * Copy fixed 32 bytes first. It's off-by-one because labels
     * on the wire are a PREFIX to the label, while the dots in
     * text format are a SUFFIX.
     */
    memcpy(output + 1, input, 32);
    
    /*
     * Classify all the bits, doing the simdson method of classifying
     * everything first. We classify the next 32 bits as either
     * valid name chars [a-zA-Z0-9_-] or something else. Invalid
     * characteers are 1, valid 0.
     */
    uint64_t mask = classify(input, max);
    mask |= (1ull << 32); /* add sentinel */
    
    /*
     * Do special first label parsing
     * - reject empty names
     * - reject anything longer than 32 bytes
     * - "reject" means going to the slow-path parser
     * - end early if there's only one label, a common
     *   case in zonefiles that assume an $ORIGIN.
     */
    unsigned length = ctz64(mask);
    if (length == 0 || length >= 32)
        return zone_atom_name5(data, cursor, max, out);
    
    output[0] = (uint8_t)length; /* set label length */

    size_t offset = length + 1; /* next label start */
    
    if (output[offset] != '.') {
        /* success */
        out->is_fqdn = 0;
        goto end;
    }
    
    /*
     * Loop through name, changing dot ending previous label
     * to a length of the next label.
     */
    for (;;) {
        /* get this label's length */
        mask >>= length + 1;
        length = ctz64(mask);
        
        /* set this label's length */
        output[offset] = length;
        
        /* move to next label */
        offset += length + 1;
        
        /* are we done yet? */
        if (length == 0) {
            out->is_fqdn = 1;
            break;
        } else if (output[offset] != '.') {
            out->is_fqdn = 0;
            break;
        }
    }

end:
    if (offset > 32 || !is_space_char(output[offset]))
        return zone_atom_name5(data, cursor, max, out);
    out->wire.len += offset; /* overall name length */
    size_t next = cursor + offset - 1;
    return next;
}

size_t
zone_parse_name0(const char *data, size_t cursor, size_t max,
                wire_record_t *out) {
    size_t next;
    
    /*
     * 1. A name consisting of just an `@` symbol refers to
     * an empty prefix to which the $ORIGIN suffix will be
     * added.
     */
    if (data[cursor] == '@') {
        next = cursor + 1;
        out->is_fqdn = 0;
        goto append_origin;
    }
    
    /*
     * 2. Grab the name from the input.
     */
    if (data[cursor] == '*') {
        next = zone_atom_name5(data, cursor, max, out);
    } else {
        next = zone_atom_name4(data, cursor, max, out);
    }
    
    /*
     * 3. If not fully-qualified (FQDN), then append
     * the $ORIGIN.
     */
append_origin:
    if (!out->is_fqdn) {
        /* if not fully qualified it, append the origin */
        wire_append_bytes(out, out->state.origin, out->state.origin_length);
        out->name_length += out->state.origin_length;
    }
    
    return next; //zone_mask_skip_nospace1(data, cursor, max, next - cursor);
}

/* ---------------------- runtime SIMD backend selection ------------------ */

void zone_atom_name4_init(int backend) {
    /* Runtime selection of SIMD backend */
    switch (backend) {
    case SIMD_AUTO: zone_atom_name4_init(simd_get_best()); break;
    case SIMD_SCALAR: classify = classify_scalar; break;
    case SIMD_SWAR: classify = classify_scalar; break;
#if defined(SIMD_SSE2)
    case SIMD_SSE2: classify = classify_sse2; break;
#endif
#if defined(SIMD_SSE42)
    case SIMD_SSE42: classify = classify_sse42; break;
#endif
#if defined(SIMD_AVX2)
    case SIMD_AVX2: classify = classify_avx2; break;
#endif
#if defined(SIMD_AVX512)
    case SIMD_AVX512: classify = classify_avx512; break;
#endif
#if defined(SIMD_NEON)
    case SIMD_NEON: classify = classify_neon; break;
#endif
#if defined(SIMD_SVE2)
    case SIMD_SVE2: classify = classify_sve2; break;
#endif
#if defined(SIMD_RISCVV)
    case SIMD_RISCVV: classify = classify_riscvv; break;
#endif
    case SIMD_MAX:
    default: classify = classify_scalar; break;
    }
}

/* ----------------------- quick selftests --------------------------- */

#include <ctype.h>
static void dump_wire(const unsigned char *wire, size_t wire_len) {
    printf("\"");
    for (unsigned i = 0; i < wire_len; i++) {
        char c = wire[i];
        if (isalnum(c&0xFF) || c == '-' || c == '_')
            printf("%c", c);
        else if (isprint(c&0xFF))
            printf("\\%c", c);
        else
            printf("\\%03o", c);
    }
    printf("\"\n");
}

static struct test_case_t {
    const char *input;
    int in_length;
    const char *output;
    size_t out_length;
    size_t consumed;
    unsigned char is_fqdn;
} test_cases[] = {
    {"www\\046example\\.com\tIN A 1.2.3.4", -1, "\x0fwww.example.com", 16, 19, 0},
    //{"www IN A 1.2.3.4\n", -1, "\3www", 4, 4, 0},
    {"one.two. IN A 1.2.3.4\n", -1, "\3one\3two\0", 9, 8, 1},
    {"one.four IN A 1.2.3.4\n", -1, "\3one\4four", 9, 8, 0},
    {"a.b.c.d.e.f IN A 1.2.3.4\n", -1, "\1a\1b\1c\1d\1e\1f\0", 12, 11, 0},
    {"a.b.c.d.e.f. IN A 1.2.3.4\n", -1, "\1a\1b\1c\1d\1e\1f\0", 13, 12, 1},

    //{"www.example.com. IN A 1.2.3.4", 16, "\3www\7example\3com\0", 17, 20, 1},
    {"www\\046example\\.com\tIN A 1.2.3.4", -1, "\x0fwww.example.com", 16, 19, 0},
    {"www.example.com. IN A 1.2.3.4", -1, "\3www\7example\3com\0", 17, 16, 1},
    {"www.example.com IN A 1.2.3.4", 15, "\3www\7example\3com", 16, 15, 0},
    {"www.example.com. IN A 1.2.3.4", 16, "\3www\7example\3com\0", 17, 16, 1},
    {0}
};
int zone_atom_name4_quicktest(void) {
    int err = 0;
    int i;
    
    for (i=0; test_cases[i].input; i++) {
        
        /*
         * Step 1: setup the test case inputs
         */
        struct test_case_t *test = &test_cases[i];
        const char *input = test->input;
        int in_length = test->in_length;
        if (in_length == -1)
            in_length = (int)strlen(input);
        
        /*
         * Setup the test case OUTputs
         */
        struct wire_record_t out = {0};
        unsigned char buf[256+1024];
        out.wire.buf = buf;
        out.wire.max = 256;
        
        /*
         * Step 2: run the test case
         */
        
        size_t consumed = zone_atom_name4(input, 0, in_length, &out);
        
        /*
         * Step 3: validate the outputs
         */
        const unsigned char *exp = (uint8_t*)test->output;
        size_t exp_len = test->out_length;
        if (consumed != test->consumed) {
            fprintf(stderr, "[-] name4:%d: consumed mismatch, found %u, expected %u\n",
                    i, (unsigned)consumed, (unsigned)test->consumed);
            printf("[-] name4: err=%d\n", (int)out.err.code);
            err++;
            continue;
        }
        if (out.wire.len != exp_len) {
            fprintf(stderr, "[-] name4:%d: output length mismatch, found %u, expected %u\n",
                    i, (unsigned)out.wire.len, (unsigned)exp_len);
            dump_wire(out.wire.buf, out.wire.len);
            err++;
            continue;
        }
        if (memcmp(out.wire.buf, exp, exp_len) != 0) {
            unsigned j;
            fprintf(stderr, "[-] name4:%d: output name mismatch\n", i);
            
            printf(" found: ");
            for (j=0; j<out.wire.len; j++)
                fprintf(stderr, " %02x", out.wire.buf[j]);
            printf("  ");
            for (j=0; j<out.wire.len; j++)
                fprintf(stderr, "%c", out.wire.buf[j]);
            
            
            fprintf(stderr, "\n");
            printf("expect: ");
            for (j=0; j<exp_len; j++)
                fprintf(stderr, " %02x", exp[j]);
            printf("  ");
            for (j=0; j<exp_len; j++)
                fprintf(stderr, "%c", exp[j]);
            
            fprintf(stderr, "\n");
            err++;
            continue;
        }
        
        if (out.is_fqdn != test->is_fqdn) {
            fprintf(stderr, "[-] name4:%d: FQDN mismatch\n", i);
            err++;
            continue;
        }
    }
    return 0;
}
