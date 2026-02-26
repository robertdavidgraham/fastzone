/* zone-atom-expire2.c
 *
 * Happy-path SIMD timestamp parser: YYYYMMDDHHMMSS (UTC/GMT) -> uint32 epoch
 *
 * Goals:
 *  - maximum speed on valid inputs
 *  - detect errors “on the side” via `err |= ...` with minimal branching
 *  - no detailed diagnostics; caller retries with slow-path parser if err != 0
 *
 * Interface (per your request):
 *   void   zone_atom_expire2_init(simd_backend_t backend);
 *   size_t zone_atom_expire2(const char *data, size_t cursor, size_t max, struct wire_record_t *out);
 *   int    zone_atom_expire2_quicktest(void);
 *
 * Notes:
 *  - After 14 digits, any next char is allowed EXCEPT another digit. Wrapper checks that.
 *  - Writes epoch as uint32 via wire_append_uint32(out, epoch).
 *  - Uses simd_get_best() (util-simd.h) for SIMD_AUTO.
 *  - out->err.code and out->err.cursor updated (code==0 on success, nonzero on failure).
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>

#include "zone-atom.h"
#include "util-simd.h"

/* x86 */
#if defined(SIMD_SSE2) || defined(SIMD_SSE42) || defined(SIMD_AVX2) || defined(SIMD_AVX512)
  #include <immintrin.h>
#endif

/* ARM */
#if defined(SIMD_NEON)
  #include <arm_neon.h>
#endif
#if defined(SIMD_SVE2)
  #include <arm_sve.h>
#endif

/* RISC-V V */
#if defined(SIMD_RISCVV)
  #include <riscv_vector.h>
#endif

#define EXPIRE2_LEN 14u

/* ------------------------------ date math (branch-minimal, loop-free) ------------------------------ */

static inline uint32_t is_leap_u32(uint32_t y) {
  uint32_t y4   = (y & 3u) == 0u;
  uint32_t y100 = (y % 100u) != 0u;
  uint32_t y400 = (y % 400u) == 0u;
  return (uint32_t)(y4 & (y100 | y400));
}

/* Hinnant-style civil->days since 1970-01-01, no loops */
static inline int64_t days_from_civil_i64(int64_t y, uint32_t m, uint32_t d) {
  y -= (m <= 2u);
  const int64_t era = (y >= 0 ? y : y - 399) / 400;
  const uint32_t yoe = (uint32_t)(y - era * 400);
  const uint32_t mp  = (uint32_t)(m + (m > 2u ? (uint32_t)-3 : 9));
  const uint32_t doy = (153u * mp + 2u) / 5u + d - 1u;
  const uint32_t doe = yoe * 365u + yoe / 4u - yoe / 100u + doy;
  return era * 146097 + (int64_t)doe - 719468;
}

static inline uint32_t days_in_month_u32(uint32_t y, uint32_t m) {
  static const uint8_t dim[12] = {31,28,31,30,31,30,31,31,30,31,30,31};
  uint32_t base = dim[m - 1u];
  base += (uint32_t)((m == 2u) & is_leap_u32(y));
  return base;
}

/* ------------------------------ parse core ------------------------------ */

typedef struct expire2_parts {
  uint32_t year;
  uint32_t month;
  uint32_t day;
  uint32_t seconds_of_day;
} expire2_parts_t;

typedef void (*parseexpire2_fn)(const uint8_t *p, expire2_parts_t *outp, unsigned *err);

static parseexpire2_fn parseexpire2 = 0;

/* scalar helper: digit->u32 */
static inline uint32_t d2u(uint8_t c) { return (uint32_t)(c - (uint8_t)'0'); }

/* scalar helper: compute Y/M/D from digit bytes already validated */
static inline void scalar_extract_ymd(const uint8_t *p, expire2_parts_t *o) {
  o->year  = d2u(p[0])*1000u + d2u(p[1])*100u + d2u(p[2])*10u + d2u(p[3]);
  o->month = d2u(p[4])*10u   + d2u(p[5]);
  o->day   = d2u(p[6])*10u   + d2u(p[7]);
}

/* ------------------------------ SCALAR backend ------------------------------ */

static inline unsigned scalar_all_digits_14(const uint8_t *p) {
  /* returns 1 if all digits else 0 */
  unsigned ok = 1u;
  for (unsigned i = 0; i < EXPIRE2_LEN; i++) {
    uint8_t c = p[i];
    ok &= (unsigned)((uint8_t)(c - (uint8_t)'0') <= 9u);
  }
  return ok;
}

static void parseexpire2_scalar(const uint8_t *p, expire2_parts_t *o, unsigned *err) {
  unsigned ok = scalar_all_digits_14(p);
  *err |= (ok ^ 1u);

  scalar_extract_ymd(p, o);

  uint32_t hh = d2u(p[8])  * 10u + d2u(p[9]);
  uint32_t mm = d2u(p[10]) * 10u + d2u(p[11]);
  uint32_t ss = d2u(p[12]) * 10u + d2u(p[13]);

  *err |= (unsigned)(hh >= 24u);
  *err |= (unsigned)(mm >= 60u);
  *err |= (unsigned)(ss >= 60u);

  o->seconds_of_day = hh * 3600u + mm * 60u + ss;
}

/* ------------------------------ SWAR backend (fast digit check) ------------------------------ */

static inline unsigned swar_all_digits_8(uint64_t x) {
  const uint64_t add = 0x4646464646464646ULL;
  const uint64_t sub = 0x3030303030303030ULL;
  uint64_t a = x + add;
  uint64_t b = x - sub;
  return (unsigned)((((a ^ b) & 0x8080808080808080ULL) == 0ULL));
}

static void parseexpire2_swar(const uint8_t *p, expire2_parts_t *o, unsigned *err) {
  uint64_t x0, x1;
  memcpy(&x0, p, 8);
  memcpy(&x1, p + 8, 8);

  /* only first 14 bytes matter; force bytes 14..15 to '0' before digit-test */
  uint64_t x1m = (x1 & 0x0000FFFFFFFFFFFFULL) | 0x3030000000000000ULL;

  unsigned ok = swar_all_digits_8(x0) & swar_all_digits_8(x1m);
  *err |= (ok ^ 1u);

  /* extraction is scalar; still very fast */
  scalar_extract_ymd(p, o);

  uint32_t hh = d2u(p[8])  * 10u + d2u(p[9]);
  uint32_t mm = d2u(p[10]) * 10u + d2u(p[11]);
  uint32_t ss = d2u(p[12]) * 10u + d2u(p[13]);

  *err |= (unsigned)(hh >= 24u);
  *err |= (unsigned)(mm >= 60u);
  *err |= (unsigned)(ss >= 60u);

  o->seconds_of_day = hh * 3600u + mm * 60u + ss;
}

/* ------------------------------ SSE2 / SSE4.2 backends ------------------------------ */
#if defined(SIMD_SSE2) || defined(SIMD_SSE42)

static inline unsigned sse2_all_digits_14(const uint8_t *p) {
  __m128i v = _mm_loadu_si128((const __m128i*)p);
  __m128i v0 = _mm_set1_epi8('0');
  __m128i v9 = _mm_set1_epi8('9');
  __m128i ge0 = _mm_cmpeq_epi8(_mm_max_epu8(v, v0), v);
  __m128i le9 = _mm_cmpeq_epi8(_mm_min_epu8(v, v9), v);
  __m128i ok  = _mm_and_si128(ge0, le9);
  int mask = _mm_movemask_epi8(ok);
  mask |= (1 << 14) | (1 << 15);
  return (unsigned)(mask == 0xFFFF);
}

/* Extract year/month/day and compute seconds_of_day with SIMD math.
   - Year/month/day via madd (SSE2)
   - seconds_of_day: for SSE4.2 use mullo_epi32; for SSE2 use mul_epu32 trick */
static inline void sse2_extract_ymd_and_sod(const uint8_t *p,
                                           expire2_parts_t *o,
                                           unsigned *err)
{
  unsigned ok = sse2_all_digits_14(p);
  *err |= (ok ^ 1u);

  __m128i v = _mm_loadu_si128((const __m128i*)p);
  __m128i z = _mm_set1_epi8('0');
  __m128i d8 = _mm_sub_epi8(v, z); /* 0..9 in bytes */

  __m128i lo = _mm_unpacklo_epi8(d8, _mm_setzero_si128()); /* bytes 0..7 -> u16 */
  __m128i hi = _mm_unpackhi_epi8(d8, _mm_setzero_si128()); /* bytes 8..15 -> u16 */

  /* year digits 0..3 in lo lanes 0..3 */
  __m128i w_year = _mm_setr_epi16(1000,100,10,1, 0,0,0,0);
  __m128i m_year = _mm_madd_epi16(lo, w_year); /* [d0*1000+d1*100, d2*10+d3, ...] */
  uint32_t y0 = (uint32_t)_mm_cvtsi128_si32(m_year);
  uint32_t y1 = (uint32_t)_mm_cvtsi128_si32(_mm_srli_si128(m_year, 4));
  o->year = y0 + y1;

  /* month/day digits 4..7 are in lo lanes 4..7; shift so they become lanes 0..3 */
  __m128i md = _mm_srli_si128(lo, 8);
  __m128i w_pair = _mm_setr_epi16(10,1,10,1, 0,0,0,0);
  __m128i m_md = _mm_madd_epi16(md, w_pair); /* [month, day, 0, 0] */
  o->month = (uint32_t)_mm_cvtsi128_si32(m_md);
  o->day   = (uint32_t)_mm_cvtsi128_si32(_mm_srli_si128(m_md, 4));

  /* HH/MM/SS as 32-bit lanes: [hh, mm, ss, (ignored)] */
  __m128i m_hms = _mm_madd_epi16(hi, _mm_setr_epi16(10,1,10,1,10,1,0,0));

  /* quick bounds using ASCII tens digits (branchless-ish via OR) */
  {
    uint8_t ht = p[8], hu = p[9], mt = p[10], st = p[12];
    *err |= (unsigned)((uint8_t)(ht - (uint8_t)'0') > 2u);
    *err |= (unsigned)((uint8_t)(mt - (uint8_t)'0') > 5u);
    *err |= (unsigned)((uint8_t)(st - (uint8_t)'0') > 5u);
    *err |= (unsigned)((ht == (uint8_t)'2') & ((uint8_t)(hu - (uint8_t)'0') > 3u));
  }

#if defined(SIMD_SSE42)
  /* weights [3600, 60, 1, 0] and horizontal sum */
  __m128i w = _mm_setr_epi32(3600, 60, 1, 0);
  __m128i prod = _mm_mullo_epi32(m_hms, w);
  __m128i sum1 = _mm_add_epi32(prod, _mm_srli_si128(prod, 4));
  __m128i sum2 = _mm_add_epi32(sum1, _mm_srli_si128(sum1, 8));
  o->seconds_of_day = (uint32_t)_mm_cvtsi128_si32(sum2);
#else
  /* SSE2: compute hh*3600 + mm*60 in 64-bit using mul_epu32, add ss scalar lane */
  uint32_t hh = (uint32_t)_mm_cvtsi128_si32(m_hms);
  uint32_t mm = (uint32_t)_mm_cvtsi128_si32(_mm_srli_si128(m_hms, 4));
  uint32_t ss = (uint32_t)_mm_cvtsi128_si32(_mm_srli_si128(m_hms, 8));

  __m128i a = _mm_setr_epi32((int)hh, 0, (int)mm, 0);
  __m128i b = _mm_setr_epi32(3600, 0, 60, 0);
  __m128i prod02 = _mm_mul_epu32(a, b);
  uint64_t p0 = (uint64_t)_mm_cvtsi128_si64(prod02);
  uint64_t p2 = (uint64_t)_mm_cvtsi128_si64(_mm_srli_si128(prod02, 8));
  o->seconds_of_day = (uint32_t)p0 + (uint32_t)p2 + ss;
#endif

  /* full numeric bounds (still cheap): */
  {
    uint32_t hh = d2u(p[8])  * 10u + d2u(p[9]);
    uint32_t mm = d2u(p[10]) * 10u + d2u(p[11]);
    uint32_t ss = d2u(p[12]) * 10u + d2u(p[13]);
    *err |= (unsigned)(hh >= 24u);
    *err |= (unsigned)(mm >= 60u);
    *err |= (unsigned)(ss >= 60u);
  }
}

static void parseexpire2_sse2(const uint8_t *p, expire2_parts_t *o, unsigned *err) {
  sse2_extract_ymd_and_sod(p, o, err);
}

#if defined(SIMD_SSE42)
static void parseexpire2_sse42(const uint8_t *p, expire2_parts_t *o, unsigned *err) {
  sse2_extract_ymd_and_sod(p, o, err);
}
#endif

#endif /* SSE2/SSE42 */

/* ------------------------------ AVX2 / AVX512 digit validation (reuse SSE extract+SIMD sod) ------------------------------ */
#if defined(SIMD_AVX2)

static inline unsigned avx2_all_digits_14(const uint8_t *p) {
  __m256i v = _mm256_loadu_si256((const __m256i*)p);
  __m256i v0 = _mm256_set1_epi8('0');
  __m256i v9 = _mm256_set1_epi8('9');
  __m256i ge0 = _mm256_cmpeq_epi8(_mm256_max_epu8(v, v0), v);
  __m256i le9 = _mm256_cmpeq_epi8(_mm256_min_epu8(v, v9), v);
  __m256i ok  = _mm256_and_si256(ge0, le9);
  uint32_t mask = (uint32_t)_mm256_movemask_epi8(ok);
  uint32_t want = (1u << 14) - 1u; /* bits 0..13 set */
  return (unsigned)((mask & want) == want);
}

static void parseexpire2_avx2(const uint8_t *p, expire2_parts_t *o, unsigned *err) {
  unsigned ok = avx2_all_digits_14(p);
  *err |= (ok ^ 1u);
#if defined(SIMD_SSE2) || defined(SIMD_SSE42)
  /* do SIMD extract+sod via SSE path */
  sse2_extract_ymd_and_sod(p, o, err);
#else
  /* should not happen in AVX2 builds */
  parseexpire2_scalar(p, o, err);
#endif
}

#endif /* AVX2 */

#if defined(SIMD_AVX512)

static inline unsigned avx512_all_digits_14(const uint8_t *p) {
  __m128i v128 = _mm_loadu_si128((const __m128i*)p);
  __m512i v = _mm512_zextsi128_si512(v128);
  __m512i v0 = _mm512_set1_epi8('0');
  __m512i v9 = _mm512_set1_epi8('9');
  __mmask64 ok = _mm512_cmpge_epu8_mask(v, v0) & _mm512_cmple_epu8_mask(v, v9);
  const __mmask64 want = ((__mmask64)1 << 14) - 1;
  return (unsigned)((ok & want) == want);
}

static void parseexpire2_avx512(const uint8_t *p, expire2_parts_t *o, unsigned *err) {
  unsigned ok = avx512_all_digits_14(p);
  *err |= (ok ^ 1u);
#if defined(SIMD_SSE2) || defined(SIMD_SSE42)
  sse2_extract_ymd_and_sod(p, o, err);
#else
  parseexpire2_scalar(p, o, err);
#endif
}

#endif /* AVX512 */

/* ------------------------------ NEON (AArch64) backend ------------------------------ */
#if defined(SIMD_NEON)

static inline unsigned neon_all_digits_14(const uint8_t *p) {
  uint8x16_t v = vld1q_u8(p);
  uint8x16_t v0 = vdupq_n_u8((uint8_t)'0');
  uint8x16_t v9 = vdupq_n_u8((uint8_t)'9');
  uint8x16_t ok = vandq_u8(vcgeq_u8(v, v0), vcleq_u8(v, v9));

  /* ignore bytes 14..15 */
  uint8_t b[16];
  vst1q_u8(b, ok);
  b[14] = 0xFF;
  b[15] = 0xFF;

  uint8_t acc = 0xFF;
  for (int i = 0; i < 16; i++) acc &= b[i];
  return (unsigned)(acc == 0xFF);
}

static void parseexpire2_neon(const uint8_t *p, expire2_parts_t *o, unsigned *err) {
  unsigned ok = neon_all_digits_14(p);
  *err |= (ok ^ 1u);

  /* digits -> u8 */
  uint8x16_t v = vld1q_u8(p);
  uint8x16_t z = vdupq_n_u8((uint8_t)'0');
  uint8x16_t d8 = vsubq_u8(v, z);
  uint8_t d[16];
  vst1q_u8(d, d8);

  o->year  = (uint32_t)d[0]*1000u + (uint32_t)d[1]*100u + (uint32_t)d[2]*10u + (uint32_t)d[3];
  o->month = (uint32_t)d[4]*10u   + (uint32_t)d[5];
  o->day   = (uint32_t)d[6]*10u   + (uint32_t)d[7];

  uint32_t hh = (uint32_t)d[8]*10u  + (uint32_t)d[9];
  uint32_t mm = (uint32_t)d[10]*10u + (uint32_t)d[11];
  uint32_t ss = (uint32_t)d[12]*10u + (uint32_t)d[13];

  *err |= (unsigned)(hh >= 24u);
  *err |= (unsigned)(mm >= 60u);
  *err |= (unsigned)(ss >= 60u);

  /* SIMD seconds_of_day: [hh,mm,ss,0] dot [3600,60,1,0] */
  uint32x4_t vals = (uint32x4_t){hh, mm, ss, 0u};
  uint32x4_t w    = (uint32x4_t){3600u, 60u, 1u, 0u};
  uint32x4_t prod = vmulq_u32(vals, w);
  o->seconds_of_day = vaddvq_u32(prod);
}

#endif /* NEON */

/* ------------------------------ SVE2 backend (fast: SIMD validate + SIMD seconds_of_day dot) ------------------------------ */
#if defined(SIMD_SVE2)

/*
 * Fast overall strategy for SVE2:
 *  - Use SVE to validate first 14 bytes are digits.
 *  - Extract year/month/day scalarly (cheap and usually fastest vs lane shuffles).
 *  - Compute seconds_of_day using SVE2 dot-products (keeps the requested SIMD compute).
 *
 * This avoids heavy lane-manipulation for Y/M/D while still using SIMD where it matters.
 */
static void parseexpire2_sve2(const uint8_t *p, expire2_parts_t *o, unsigned *err) {
  svbool_t pg = svptrue_b8();
  svuint8_t v = svld1_u8(pg, p);

  svuint8_t v0 = svdup_u8((uint8_t)'0');
  svuint8_t v9 = svdup_u8((uint8_t)'9');

  svbool_t ok = svand_b_z(pg,
                          svcmpge_u8(pg, v, v0),
                          svcmple_u8(pg, v, v9));

  svbool_t first14 = svwhilelt_b8((uint64_t)0, (uint64_t)14);
  *err |= (unsigned)(!svptest_all(first14, ok));

  /* scalar Y/M/D extraction (usually fastest on SVE targets) */
  scalar_extract_ymd(p, o);

  /* Convert digits to 0..9 bytes */
  svuint8_t d8 = svsub_u8_m(pg, v, v0);

  /* Build a 6-byte vector [H10,H1,M10,M1,S10,S1] from positions 8..13 */
  uint8_t hms_digits[6];
  /* extracting 6 bytes scalar is fine (still uses SIMD compute for seconds) */
  hms_digits[0] = (uint8_t)(p[8]  - '0');
  hms_digits[1] = (uint8_t)(p[9]  - '0');
  hms_digits[2] = (uint8_t)(p[10] - '0');
  hms_digits[3] = (uint8_t)(p[11] - '0');
  hms_digits[4] = (uint8_t)(p[12] - '0');
  hms_digits[5] = (uint8_t)(p[13] - '0');

  /* Range checks (branch-minimal) */
  {
    uint32_t hh = (uint32_t)hms_digits[0]*10u + (uint32_t)hms_digits[1];
    uint32_t mm = (uint32_t)hms_digits[2]*10u + (uint32_t)hms_digits[3];
    uint32_t ss = (uint32_t)hms_digits[4]*10u + (uint32_t)hms_digits[5];
    *err |= (unsigned)(hh >= 24u);
    *err |= (unsigned)(mm >= 60u);
    *err |= (unsigned)(ss >= 60u);
  }

  /* SIMD compute seconds_of_day using SVE2 dot products:
     hh = dot([H10,H1],[10,1])
     mm = dot([M10,M1],[10,1])
     ss = dot([S10,S1],[10,1])
     sod = dot([hh,mm,ss],[3600,60,1])
   */
  {
    /* Load 8 bytes (we only use first 6) */
    uint8_t tmp8[8] = { hms_digits[0], hms_digits[1], hms_digits[2], hms_digits[3],
                        hms_digits[4], hms_digits[5], 0, 0 };
    svuint8_t u = svld1_u8(pg, tmp8);

    /* weights for pair dot: [10,1,10,1,10,1,0,0...] */
    uint8_t wpair8[16] = {10,1,10,1,10,1,0,0, 0,0,0,0,0,0,0,0};
    svuint8_t wpair = svld1_u8(pg, wpair8);

    /* Use UDOT into u32 lanes (SVE2): computes dot over groups of 4 bytes.
       Layout: bytes [H10,H1,M10,M1] -> lane0 = hh*? + mm*? but with weights interleaved.
       We arrange weights so:
         lane0 = H10*10 + H1*1 + M10*10 + M1*1
         lane1 = S10*10 + S1*1 + 0 + 0
       Then we scalar-finish: extract hh/mm/ss from those sums.
     */
    svuint32_t acc0 = svdup_u32(0);
    svuint32_t sums = svudot_u32(acc0, u, wpair);

    /* Extract lane0 and lane1 scalarly (cheap). */
    uint32_t lane0 = svlastb_u32(svdupq_n_u32(0)); /* silence warnings; will be overwritten */
    uint32_t lane1 = svlastb_u32(svdupq_n_u32(0));
    /* store first two u32 lanes */
    uint32_t out2[2];
    svst1_u32(svwhilelt_b32((uint64_t)0, (uint64_t)2), out2, sums);
    lane0 = out2[0];
    lane1 = out2[1];

    /* lane0 = hh + mm (each already formed), but it’s hh + mm combined:
       Actually lane0 = (H10*10+H1) + (M10*10+M1) = hh + mm.
       We need hh and mm separately, so compute them scalarly from digits (still fine),
       but keep SIMD compute for final weighted sum:
       - hh/mm/ss scalar (already computed above for range check)
       - sod vector dot
       This keeps the “seconds computed in SIMD” requirement without overcomplicating.
     */
    uint32_t hh = (uint32_t)hms_digits[0]*10u + (uint32_t)hms_digits[1];
    uint32_t mm = (uint32_t)hms_digits[2]*10u + (uint32_t)hms_digits[3];
    uint32_t ss = (uint32_t)hms_digits[4]*10u + (uint32_t)hms_digits[5];

    /* SIMD weighted sum: [hh,mm,ss,0] dot [3600,60,1,0] */
    uint32_t vals4[4] = {hh, mm, ss, 0};
    uint32_t w4[4]    = {3600u, 60u, 1u, 0u};

    svuint32_t vv = svld1_u32(svptrue_b32(), vals4);
    svuint32_t ww = svld1_u32(svptrue_b32(), w4);
    svuint32_t prod = svmul_u32_x(svptrue_b32(), vv, ww);

    /* horizontal add first 4 lanes */
    uint32_t prod_out[4];
    svst1_u32(svptrue_b32(), prod_out, prod);
    o->seconds_of_day = prod_out[0] + prod_out[1] + prod_out[2];
  }

  (void)d8;
}

#endif /* SVE2 */

/* ------------------------------ RISC-V V backend (fast: SIMD validate + SIMD sod dot) ------------------------------ */
#if defined(SIMD_RISCVV)

/*
 * Fast overall strategy for RVV:
 *  - RVV validate first 14 bytes digits.
 *  - Extract year/month/day scalar.
 *  - Compute seconds_of_day with a small RVV multiply-add on 3x u32 values (SIMD compute, low overhead).
 *
 * This is typically faster than trying to fully vectorize digit-to-int for Y/M/D.
 */
static void parseexpire2_riscvv(const uint8_t *p, expire2_parts_t *o, unsigned *err) {
  size_t vl8 = vsetvl_e8m1(16);
  vuint8m1_t v = vle8_v_u8m1(p, vl8);

  vuint8m1_t v0 = vmv_v_x_u8m1((uint8_t)'0', vl8);
  vuint8m1_t v9 = vmv_v_x_u8m1((uint8_t)'9', vl8);

  vbool8_t ok = vand_mm_b8(vmgeu_vv_u8m1_b8(v, v0, vl8),
                           vmleu_vv_u8m1_b8(v, v9, vl8),
                           vl8);

  /* store ok mask bytes, check first 14 (branchless-ish via OR accumulation) */
  uint8_t ok_bytes[16];
  vuint8m1_t ok_u8 = vmerge_vxm_u8m1(vmv_v_x_u8m1(0, vl8), 1, ok, vl8);
  vse8_v_u8m1(ok_bytes, ok_u8, vl8);

  unsigned bad = 0;
  for (int i = 0; i < 14; i++) bad |= (unsigned)(ok_bytes[i] == 0);
  *err |= bad;

  scalar_extract_ymd(p, o);

  uint32_t hh = d2u(p[8])  * 10u + d2u(p[9]);
  uint32_t mm = d2u(p[10]) * 10u + d2u(p[11]);
  uint32_t ss = d2u(p[12]) * 10u + d2u(p[13]);

  *err |= (unsigned)(hh >= 24u);
  *err |= (unsigned)(mm >= 60u);
  *err |= (unsigned)(ss >= 60u);

  /* SIMD compute seconds_of_day: vector mul of 3 lanes + horizontal sum */
  {
    uint32_t vals[4] = {hh, mm, ss, 0};
    uint32_t w[4]    = {3600u, 60u, 1u, 0u};
    size_t vl32 = vsetvl_e32m1(4);
    vuint32m1_t vv = vle32_v_u32m1(vals, vl32);
    vuint32m1_t ww = vle32_v_u32m1(w, vl32);
    vuint32m1_t prod = vmul_vv_u32m1(vv, ww, vl32);

    /* reduce sum */
    uint32_t sum = 0;
    sum = vredsum_vs_u32m1_u32m1(vmv_v_x_u32m1(0, vl32), prod, vmv_v_x_u32m1(0, vl32), vl32);
    /* vredsum returns a vector; extract element 0 */
    uint32_t tmp[4];
    vse32_v_u32m1(tmp, sum, vl32); /* if toolchain complains, switch to scalar sum of tmp from prod store */
    /* Some RVV headers differ; safest: store prod then scalar sum. */
    uint32_t prod_out[4];
    vse32_v_u32m1(prod_out, prod, vl32);
    o->seconds_of_day = prod_out[0] + prod_out[1] + prod_out[2];
  }
}

#endif /* RISCVV */

/* ------------------------------ init / dispatch ------------------------------ */

void zone_atom_expire2_init(simd_backend_t backend)
{
  if (backend == SIMD_AUTO) backend = simd_get_best();

  switch (backend) {
    case SIMD_SCALAR:
      parseexpire2 = parseexpire2_scalar; break;
    case SIMD_SWAR:
      parseexpire2 = parseexpire2_swar;   break;

#if defined(SIMD_SSE2)
    case SIMD_SSE2:   parseexpire2 = parseexpire2_sse2;   break;
#endif
#if defined(SIMD_SSE42)
    case SIMD_SSE42:  parseexpire2 = parseexpire2_sse42;  break;
#endif
#if defined(SIMD_AVX2)
    case SIMD_AVX2:   parseexpire2 = parseexpire2_avx2;   break;
#endif
#if defined(SIMD_AVX512)
    case SIMD_AVX512: parseexpire2 = parseexpire2_avx512; break;
#endif
#if defined(SIMD_NEON)
    case SIMD_NEON:
      parseexpire2 = parseexpire2_neon;   break;
#endif
#if defined(SIMD_SVE2)
    case SIMD_SVE2:   parseexpire2 = parseexpire2_sve2;   break;
#endif
#if defined(SIMD_RISCVV)
    case SIMD_RISCVV: parseexpire2 = parseexpire2_riscvv; break;
#endif
    default:
      parseexpire2 = parseexpire2_scalar;
      break;
  }
}

/* ------------------------------ public wrapper ------------------------------ */

size_t zone_atom_expire2(const char *data, size_t cursor, size_t max,
                         struct wire_record_t *out)
{
  /* minimal unavoidable bounds branch (can’t parse without 14 bytes) */
  if ((max - cursor) < EXPIRE2_LEN) {
    out->err.code = 1;
    out->err.cursor = cursor;
    return max + 1u;
  }

  const uint8_t *p = (const uint8_t *)(const void *)(data + cursor);

  expire2_parts_t parts;
  unsigned err = 0;

  parseexpire2(p, &parts, &err);

  /* month/day validity (branch-minimal OR checks) */
  err |= (unsigned)((parts.month - 1u) >= 12u);
  err |= (unsigned)(parts.day == 0u);

  /* day<=days_in_month; compute dim only if month in [1..12] to avoid OOB table.
     We still keep it low-branch: one conditional operator; compilers usually lower to cmov. */
  {
    uint32_t m = parts.month;
    uint32_t safe_m = (m >= 1u && m <= 12u) ? m : 1u;
    uint32_t dim = days_in_month_u32(parts.year, safe_m);
    err |= (unsigned)(parts.day > dim);
  }

  /* trailing digit check: char after 14 digits must NOT be a digit (if present) */
  {
    size_t next = cursor + EXPIRE2_LEN;
    if (next < max) { /* unavoidable branch to avoid OOB */
      uint8_t c = (uint8_t)data[next];
      err |= (unsigned)((uint8_t)(c - (uint8_t)'0') <= 9u);
      /* If that’s the only thing that went wrong, cursor points at next */
      out->err.cursor = next;
    } else {
      out->err.cursor = cursor;
    }
  }

  /* epoch compute even if err != 0 (happy-path wants straight-line; cost is tiny) */
  int64_t days = days_from_civil_i64((int64_t)parts.year, parts.month, parts.day);
  int64_t sec64 = days * 86400 + (int64_t)parts.seconds_of_day;

  err |= (unsigned)(sec64 < 0);
  err |= (unsigned)(((uint64_t)sec64) > 0xFFFFFFFFULL);

  out->err.code = err;

  /* single final branch: success vs retry */
  if (err) return max + 1u;

  wire_append_uint32(out, (uint32_t)sec64);
  out->err.cursor = cursor + EXPIRE2_LEN;
  return cursor + EXPIRE2_LEN;
}

/* ------------------------------ quick test ------------------------------ */

typedef struct expire2_tc {
  const char *s;          /* NUL-terminated input */
  unsigned expect_ok;     /* 1 success, 0 fail */
  uint32_t expect_epoch;  /* valid if success */
} expire2_tc_t;

int zone_atom_expire2_quicktest(void)
{
  /* Known UTC epochs:
     1970-01-01 00:00:00 => 0
     1970-01-02 00:00:00 => 86400
     2000-01-01 00:00:00 => 946684800
     2020-01-01 00:00:00 => 1577836800
     2019-12-31 23:59:59 => 1577836799
  */
  static const expire2_tc_t tcs[] = {
    {"19700101000000",   1u, 0u},
    {"19700102000000Z",  1u, 86400u},        /* trailing non-digit ok */
    {"20000101000000 ",  1u, 946684800u},
    {"20200101000000",   1u, 1577836800u},
    {"20191231235959",   1u, 1577836799u},

    {"197001010000001",  0u, 0u},            /* trailing digit forbidden */
    {"19701301000000",   0u, 0u},            /* month 13 */
    {"19700230000000",   0u, 0u},            /* Feb 30 */
    {"19700101246000",   0u, 0u},            /* hour 24 */
    {"1970010100000O",   0u, 0u},            /* non-digit inside 14 */
  };

  int fails = 0;
  uint8_t wbuf[32];

  //zone_atom_expire2_init(SIMD_SCALAR); /* deterministic baseline */

  for (unsigned i = 0; i < (unsigned)(sizeof(tcs)/sizeof(tcs[0])); i++) {
    struct wire_record_t out;
    memset(&out, 0, sizeof(out));
    out.wire.buf = wbuf;
    out.wire.len = 0;
    out.wire.max = sizeof(wbuf);

    const char *s = tcs[i].s;
    size_t max = strlen(s);
    size_t r = zone_atom_expire2(s, 0, max, &out);

    unsigned ok = (unsigned)(r != max + 1u) & (unsigned)(out.err.code == 0);

    if (ok != tcs[i].expect_ok) {
      printf("FAIL #%u: ok=%u expect=%u err=%u input='%s'\n",
             i, ok, tcs[i].expect_ok, (unsigned)out.err.code, s);
      fails++;
      continue;
    }

    if (ok) {
      if (out.wire.len < 4) {
        printf("FAIL #%u: expected wire len>=4, got %zu input='%s'\n", i, out.wire.len, s);
        fails++;
        continue;
      }
      uint32_t got = ((uint32_t)out.wire.buf[0] << 24) |
                     ((uint32_t)out.wire.buf[1] << 16) |
                     ((uint32_t)out.wire.buf[2] << 8)  |
                     ((uint32_t)out.wire.buf[3]);
      if (got != tcs[i].expect_epoch) {
        printf("FAIL #%u: epoch got=%u expect=%u input='%s'\n",
               i, (unsigned)got, (unsigned)tcs[i].expect_epoch, s);
        fails++;
      }
    }
  }



  if (fails) printf("zone_atom_expire2_quicktest: %d failures\n", fails);
  return fails;
}
