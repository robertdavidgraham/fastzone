// zone-token.c
//
// Runtime-selectable tokenizer backend (scalar/SWAR/SSE2/SSE4.2/AVX2/AVX512/NEON).
// User can force a specific backend by calling zone_tokenizer_set_backend().
// Or choose SIMD_AUTO to pick the best available at runtime.
//
// Assumptions:
// - record ends with '\n' and a CRLF/LF occurs before maxlen (so no need to bounds-check for EOL).
// - zone_rrtype_lookup() is defined elsewhere (perfect hash etc).
//
// In-place normalization:
// - tabs, parentheses, CR/LF inside parens, and comment bytes are converted to ' '.
// - parentheses bytes '(' and ')' are converted to ' ' and only affect paren_depth.
// Tokenization rules:
// - quoted strings are single tokens and may contain spaces; \" and \x escapes are handled by skipping next byte.
// - unquoted tokens end at space/tab/comment/paren/eol, but backslash escapes a following space/tab/etc,
//   so scanning must skip escaped bytes.
#include "zone-token.h"
#include "zone-rrtype.h"
#include "util-simd.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>



static int _zone_tokenize_quicktest(int backend);

// ----------------------------- backend selection -----------------------------



// Set forced backend (or AUTO).
void zone_tokenizer_init(simd_backend_t b) {
    g_zone_backend = b;
}

// Read current setting.
simd_backend_t zone_tokenizer_get_backend(void) { return (simd_backend_t)g_zone_backend; }

// ----------------------------- utilities -----------------------------

static inline uint8_t zone_is_eol(uint8_t c) { return (c == '\n' || c == '\r'); }

static inline uint8_t zone_tolower_ascii(uint8_t c) {
  if (c >= 'A' && c <= 'Z') return (uint8_t)(c + 32);
  return c;
}

static inline int zone_memicmp_ascii(const char *a, const char *b, size_t n) {
  for (size_t i = 0; i < n; i++) {
    uint8_t ca = zone_tolower_ascii((uint8_t)a[i]);
    uint8_t cb = zone_tolower_ascii((uint8_t)b[i]);
    if (ca != cb) return (ca < cb) ? -1 : 1;
  }
  return 0;
}



static int zone_parse_ttl_seconds(const char *s, size_t n, uint32_t *ttl_out) {
  if (n == 0) return 0;
  uint64_t total = 0;
  size_t i = 0;

  while (i < n) {
    if ((uint8_t)s[i] < '0' || (uint8_t)s[i] > '9') return 0;
    uint64_t num = 0;
    while (i < n) {
      uint8_t c = (uint8_t)s[i];
      if (c < '0' || c > '9') break;
      num = num * 10 + (uint64_t)(c - '0');
      if (num > 0xFFFFFFFFu) return 0;
      i++;
    }

    uint64_t mult = 1;
    if (i < n) {
      uint8_t u = zone_tolower_ascii((uint8_t)s[i]);
      if (u == 'w') { mult = 7ull * 24ull * 3600ull; i++; }
      else if (u == 'd') { mult = 24ull * 3600ull; i++; }
      else if (u == 'h') { mult = 3600ull; i++; }
      else if (u == 'm') { mult = 60ull; i++; }
      else if (u == 's') { mult = 1ull; i++; }
      else return 0;
    }
    total += num * mult;
    if (total > 0xFFFFFFFFu) return 0;
  }

  *ttl_out = (uint32_t)total;
  return 1;
}

static int zone_parse_class(const char *s, size_t n, uint16_t *cls_out) {
  if (n == 2) {
    if (!zone_memicmp_ascii(s, "IN", 2)) { *cls_out = ZONE_CLASS_IN; return 1; }
    if (!zone_memicmp_ascii(s, "CH", 2)) { *cls_out = ZONE_CLASS_CH; return 1; }
    if (!zone_memicmp_ascii(s, "HS", 2)) { *cls_out = ZONE_CLASS_HS; return 1; }
    if (!zone_memicmp_ascii(s, "CS", 2)) { *cls_out = ZONE_CLASS_CS; return 1; }
  }
  return 0;
}

// ------------------------- "find special" primitives -------------------------

static inline int zone_is_special_byte(uint8_t c, int in_parens) {
  if (c == ' ' || c == '\t' || c == ';' || c == '(' || c == ')' || c == '\\' || c == '"') return 1;
  if (in_parens && (c == '\n' || c == '\r')) return 1;
  if (!in_parens && (c == '\n' || c == '\r')) return 1;
  return 0;
}

typedef const char* (*zone_find_special_fn)(const char *p, const char *end, int in_parens);

static const char* find_special_scalar(const char *p, const char *end, int in_parens) {
  while (p < end) {
    if (zone_is_special_byte((uint8_t)*p, in_parens)) return p;
    p++;
  }
  return end;
}

// SWAR: 8-byte scan
static inline uint64_t zone_swar_has_byte(uint64_t x, uint8_t c) {
  uint64_t k = 0x0101010101010101ull * (uint64_t)c;
  uint64_t v = x ^ k;
  return (v - 0x0101010101010101ull) & ~v & 0x8080808080808080ull;
}

static const char* find_special_swar(const char *p, const char *end, int in_parens) {
  const char *q = p;
  while (((uintptr_t)q & 7) && q < end) {
    if (zone_is_special_byte((uint8_t)*q, in_parens)) return q;
    q++;
  }
  while (q + 8 <= end) {
    uint64_t x;
    memcpy(&x, q, 8);
    uint64_t m = 0;
    m |= zone_swar_has_byte(x, (uint8_t)' ');
    m |= zone_swar_has_byte(x, (uint8_t)'\t');
    m |= zone_swar_has_byte(x, (uint8_t)';');
    m |= zone_swar_has_byte(x, (uint8_t)'(');
    m |= zone_swar_has_byte(x, (uint8_t)')');
    m |= zone_swar_has_byte(x, (uint8_t)'\\');
    m |= zone_swar_has_byte(x, (uint8_t)'"');
    m |= zone_swar_has_byte(x, (uint8_t)'\n');
    m |= zone_swar_has_byte(x, (uint8_t)'\r');
    if (m) {
      for (int i = 0; i < 8; i++) {
        if (zone_is_special_byte((uint8_t)q[i], in_parens)) return q + i;
      }
    }
    q += 8;
  }
  return find_special_scalar(q, end, in_parens);
}

#if ZONE_X86
__attribute__((target("sse2")))
static const char* find_special_sse2(const char *p, const char *end, int in_parens) {
  (void)in_parens;
  const __m128i v_sp  = _mm_set1_epi8(' ');
  const __m128i v_tb  = _mm_set1_epi8('\t');
  const __m128i v_sc  = _mm_set1_epi8(';');
  const __m128i v_lp  = _mm_set1_epi8('(');
  const __m128i v_rp  = _mm_set1_epi8(')');
  const __m128i v_bs  = _mm_set1_epi8('\\');
  const __m128i v_qt  = _mm_set1_epi8('"');
  const __m128i v_nl  = _mm_set1_epi8('\n');
  const __m128i v_cr  = _mm_set1_epi8('\r');

  const char *q = p;
  while (q + 16 <= end) {
    __m128i x = _mm_loadu_si128((const __m128i*)q);
    __m128i m = _mm_or_si128(_mm_cmpeq_epi8(x, v_sp), _mm_cmpeq_epi8(x, v_tb));
    m = _mm_or_si128(m, _mm_cmpeq_epi8(x, v_sc));
    m = _mm_or_si128(m, _mm_cmpeq_epi8(x, v_lp));
    m = _mm_or_si128(m, _mm_cmpeq_epi8(x, v_rp));
    m = _mm_or_si128(m, _mm_cmpeq_epi8(x, v_bs));
    m = _mm_or_si128(m, _mm_cmpeq_epi8(x, v_qt));
    m = _mm_or_si128(m, _mm_cmpeq_epi8(x, v_nl));
    m = _mm_or_si128(m, _mm_cmpeq_epi8(x, v_cr));
    int mask = _mm_movemask_epi8(m);
    if (mask) return q + __builtin_ctz((unsigned)mask);
    q += 16;
  }
  return find_special_scalar(q, end, in_parens);
}

__attribute__((target("sse4.2")))
static const char* find_special_sse42(const char *p, const char *end, int in_parens) {
  (void)in_parens;
  const __m128i set = _mm_setr_epi8(' ', '\t', ';', '(', ')', '\\', '"', '\n', '\r', 0, 0, 0, 0, 0, 0, 0);
  const char *q = p;
  while (q < end) {
    size_t remaining = (size_t)(end - q);
    int len = (remaining >= 16) ? 16 : (int)remaining;
    __m128i chunk = _mm_loadu_si128((const __m128i*)q);
    int idx = _mm_cmpestri(set, 9, chunk, len, _SIDD_CMP_EQUAL_ANY);
    if (idx != len) return q + idx;
    q += len;
  }
  return end;
}

__attribute__((target("avx2")))
static const char* find_special_avx2(const char *p, const char *end, int in_parens) {
  (void)in_parens;
  const __m256i v_sp  = _mm256_set1_epi8(' ');
  const __m256i v_tb  = _mm256_set1_epi8('\t');
  const __m256i v_sc  = _mm256_set1_epi8(';');
  const __m256i v_lp  = _mm256_set1_epi8('(');
  const __m256i v_rp  = _mm256_set1_epi8(')');
  const __m256i v_bs  = _mm256_set1_epi8('\\');
  const __m256i v_qt  = _mm256_set1_epi8('"');
  const __m256i v_nl  = _mm256_set1_epi8('\n');
  const __m256i v_cr  = _mm256_set1_epi8('\r');

  const char *q = p;
  while (q + 32 <= end) {
    __m256i x = _mm256_loadu_si256((const __m256i*)q);
    __m256i m = _mm256_or_si256(_mm256_cmpeq_epi8(x, v_sp), _mm256_cmpeq_epi8(x, v_tb));
    m = _mm256_or_si256(m, _mm256_cmpeq_epi8(x, v_sc));
    m = _mm256_or_si256(m, _mm256_cmpeq_epi8(x, v_lp));
    m = _mm256_or_si256(m, _mm256_cmpeq_epi8(x, v_rp));
    m = _mm256_or_si256(m, _mm256_cmpeq_epi8(x, v_bs));
    m = _mm256_or_si256(m, _mm256_cmpeq_epi8(x, v_qt));
    m = _mm256_or_si256(m, _mm256_cmpeq_epi8(x, v_nl));
    m = _mm256_or_si256(m, _mm256_cmpeq_epi8(x, v_cr));
    unsigned mask = (unsigned)_mm256_movemask_epi8(m);
    if (mask) return q + __builtin_ctz(mask);
    q += 32;
  }
  return find_special_sse2(q, end, in_parens);
}

#if defined(__AVX512F__)
__attribute__((target("avx512f,avx512bw")))
static const char* find_special_avx512(const char *p, const char *end, int in_parens) {
  (void)in_parens;
  const __m512i v_sp  = _mm512_set1_epi8(' ');
  const __m512i v_tb  = _mm512_set1_epi8('\t');
  const __m512i v_sc  = _mm512_set1_epi8(';');
  const __m512i v_lp  = _mm512_set1_epi8('(');
  const __m512i v_rp  = _mm512_set1_epi8(')');
  const __m512i v_bs  = _mm512_set1_epi8('\\');
  const __m512i v_qt  = _mm512_set1_epi8('"');
  const __m512i v_nl  = _mm512_set1_epi8('\n');
  const __m512i v_cr  = _mm512_set1_epi8('\r');

  const char *q = p;
  while (q + 64 <= end) {
    __m512i x = _mm512_loadu_si512((const void*)q);
    __mmask64 m = 0;
    m |= _mm512_cmpeq_epi8_mask(x, v_sp);
    m |= _mm512_cmpeq_epi8_mask(x, v_tb);
    m |= _mm512_cmpeq_epi8_mask(x, v_sc);
    m |= _mm512_cmpeq_epi8_mask(x, v_lp);
    m |= _mm512_cmpeq_epi8_mask(x, v_rp);
    m |= _mm512_cmpeq_epi8_mask(x, v_bs);
    m |= _mm512_cmpeq_epi8_mask(x, v_qt);
    m |= _mm512_cmpeq_epi8_mask(x, v_nl);
    m |= _mm512_cmpeq_epi8_mask(x, v_cr);
    if (m) return q + __builtin_ctzll((unsigned long long)m);
    q += 64;
  }
  return find_special_avx2(q, end, in_parens);
}
#endif
#endif // ZONE_X86

#if ZONE_ARM && defined(__ARM_NEON)
static const char* find_special_neon(const char *p, const char *end, int in_parens) {
  (void)in_parens;
  const uint8x16_t v_sp = vdupq_n_u8((uint8_t)' ');
  const uint8x16_t v_tb = vdupq_n_u8((uint8_t)'\t');
  const uint8x16_t v_sc = vdupq_n_u8((uint8_t)';');
  const uint8x16_t v_lp = vdupq_n_u8((uint8_t)'(');
  const uint8x16_t v_rp = vdupq_n_u8((uint8_t)')');
  const uint8x16_t v_bs = vdupq_n_u8((uint8_t)'\\');
  const uint8x16_t v_qt = vdupq_n_u8((uint8_t)'"');
  const uint8x16_t v_nl = vdupq_n_u8((uint8_t)'\n');
  const uint8x16_t v_cr = vdupq_n_u8((uint8_t)'\r');

  const char *q = p;
  while (q + 16 <= end) {
    uint8x16_t x = vld1q_u8((const uint8_t*)q);
    uint8x16_t m = vceqq_u8(x, v_sp);
    m = vorrq_u8(m, vceqq_u8(x, v_tb));
    m = vorrq_u8(m, vceqq_u8(x, v_sc));
    m = vorrq_u8(m, vceqq_u8(x, v_lp));
    m = vorrq_u8(m, vceqq_u8(x, v_rp));
    m = vorrq_u8(m, vceqq_u8(x, v_bs));
    m = vorrq_u8(m, vceqq_u8(x, v_qt));
    m = vorrq_u8(m, vceqq_u8(x, v_nl));
    m = vorrq_u8(m, vceqq_u8(x, v_cr));
    uint64_t hi = vgetq_lane_u64(vreinterpretq_u64_u8(m), 1);
    uint64_t lo = vgetq_lane_u64(vreinterpretq_u64_u8(m), 0);
    if ((hi | lo) != 0) {
      for (int i = 0; i < 16; i++) {
        if (zone_is_special_byte((uint8_t)q[i], in_parens)) return q + i;
      }
    }
    q += 16;
  }
  return find_special_scalar(q, end, in_parens);
}
#endif

static zone_find_special_fn zone_pick_best_special_finder(void) {
#if ZONE_ARM && defined(__ARM_NEON)
  return find_special_neon;
#endif

#if ZONE_X86
  #if defined(__clang__) || defined(__GNUC__)
    #if defined(__AVX512F__)
      if (__builtin_cpu_supports("avx512bw") && __builtin_cpu_supports("avx512f")) return find_special_avx512;
    #endif
    if (__builtin_cpu_supports("avx2")) return find_special_avx2;
    if (__builtin_cpu_supports("sse4.2")) return find_special_sse42;
    if (__builtin_cpu_supports("sse2")) return find_special_sse2;
  #endif
#endif

  return find_special_swar; // usually beats scalar; still safe everywhere
}

static zone_find_special_fn zone_pick_forced_special_finder(simd_backend_t b) {
  switch (b) {
    case SIMD_SCALAR: return find_special_scalar;
    case SIMD_SWAR:   return find_special_swar;

#if ZONE_X86
    case SIMD_SSE2:   return find_special_sse2;
    case SIMD_SSE42:  return find_special_sse42;
    case SIMD_AVX2:   return find_special_avx2;
    #if defined(__AVX512F__)
      case SIMD_AVX512: return find_special_avx512;
    #endif
#endif

#if ZONE_ARM && defined(__ARM_NEON)
    case SIMD_NEON:   return find_special_neon;
#endif

    case SIMD_AUTO:
    default:
      return zone_pick_best_special_finder();
  }
}

// ----------------------------- tokenizer core -----------------------------

static inline void zone_to_space(char *p) {
    *p = ' ';
}

static char* zone_skip_junk(char *p, int *paren_depth) {
    for (;;) {
        uint8_t c = (uint8_t)*p;
        
        if (c == ' ' || c == '\t') {
            zone_to_space(p);
            p++;
            continue;
        }
        
        if (c == ';') {
            zone_to_space(p); p++;
            for (;;) {
                uint8_t d = (uint8_t)*p;
                if (d == '\n') { zone_to_space(p); p++; break; }
                if (d == '\r') {
                    zone_to_space(p); p++;
                    if ((uint8_t)*p == '\n') { zone_to_space(p); p++; }
                    break;
                }
                zone_to_space(p); p++;
            }
            continue;
        }
        
        if (c == '(') {
            zone_to_space(p);
            (*paren_depth)++;
            p++;
            continue;
        }
        if (c == ')') {
            zone_to_space(p);
            if (*paren_depth <= 0) return NULL;
            (*paren_depth)--;
            p++;
            continue;
        }
        
        if (*paren_depth > 0 && (c == '\n' || c == '\r')) {
            zone_to_space(p);
            p++;
            continue;
        }
        
        return p;
    }
}

static char* zone_scan_quoted(char *p) {
  p++; // past opening "
  for (;;) {
    uint8_t c = (uint8_t)*p;
    if (c == '\\') { p += 2; continue; }
    if (c == '"') { p++; return p; }
    if (c == '\n' || c == '\r') return NULL;
    p++;
  }
}

static char* zone_scan_unquoted(char *p, char *end, int paren_depth, zone_find_special_fn find_special) {
  for (;;) {
    const char *hit = find_special(p, end, paren_depth > 0);
    if (hit == end) return end;

    uint8_t c = (uint8_t)*hit;

    if (c == '\\') {
      // skip '\' + escaped byte (may be space/tab etc.)
      char *q = (char*)hit;
      q += 2;
      p = q;
      continue;
    }

    return (char*)hit;
  }
}

// ----------------------------- zone_tokenize -----------------------------

int zone_tokenize(char *rec, size_t maxlen, struct zone_tokenized *out) {
    if (!rec || !out) return ZONE_ERR_SYNTAX;
    memset(out, 0, sizeof(*out));
    
    simd_backend_t forced = (simd_backend_t)g_zone_backend;
    zone_find_special_fn find_special = zone_pick_forced_special_finder(forced);
    
    char *base = rec;
    char *p = rec;
    char *end = rec + maxlen;
    
    int paren_depth = 0;
    
    // Read up to 3 initial tokens to resolve TTL/CLASS/TYPE.
    const char *t[3] = {0,0,0};
    size_t tn[3] = {0,0,0};
    
    for (int i = 0; i < 3; i++) {
        p = zone_skip_junk(p, &paren_depth);
        if (!p)
            return ZONE_ERR_SYNTAX;
        
        if (paren_depth == 0 && zone_is_eol((uint8_t)*p))
            break;
        if ((uint8_t)*p == '"')
            break;
        
        char *after = zone_scan_unquoted(p, end, paren_depth, find_special);
        t[i] = p;
        tn[i] = (size_t)(after - p);
        p = after;
        
        char *peek = zone_skip_junk(p, &paren_depth);
        if (!peek)
            return ZONE_ERR_SYNTAX;
        if (paren_depth == 0 && zone_is_eol((uint8_t)*peek)) { p = peek; break; }
    }
        
    int i;
    for (i = 0; i < 3; i++) {
        if (!t[i] || tn[i] == 0)
            break;
        uint32_t ttl;
        uint16_t cls;
        
        if (!out->has_ttl && zone_parse_ttl_seconds(t[i], tn[i], &ttl)) {
            out->has_ttl = 1;
            out->ttl_seconds = ttl;
        } else if (!out->has_class && zone_parse_class(t[i], tn[i], &cls)) {
            out->has_class = 1;
            out->rrclass = cls;
        } else
            break;
    }
    
    int type_index = i;
    const char *type_s = t[i];
    size_t type_n = tn[i];
    if (!type_s || type_n == 0)
        return ZONE_ERR_EMPTY_TYPE;
    
    const struct rrtype_t *rr_type = 0;
    int err;
    err = zone_rrtype_lookup(type_s, type_n, &rr_type);
    if (err)
        return ZONE_ERR_BAD_TYPE;
    
    out->rr_type = rr_type;
    out->type_tok.off = (uint32_t)(type_s - base);
    out->type_tok.len = (uint32_t)type_n;
    
    // Any collected token after TYPE that wasn't TTL/CLASS becomes initial RRDATA tokens.
    out->rrtoken_count = 0;
    for (i = type_index+1; i < 3; i++) {
        if (!t[i] || tn[i] == 0)
            break;
        
        if (out->rrtoken_count >= ZONE_MAX_RRTOKENS)
            return ZONE_ERR_TOO_MANY_TOKENS;
        out->rrtokens[out->rrtoken_count].off = (uint32_t)(t[i] - base);
        out->rrtokens[out->rrtoken_count].len = (uint32_t)tn[i];
        out->rrtoken_count++;
    }
    
    // Continue RRDATA tokenization.
    while (p < end) {
        char *q = zone_skip_junk(p, &paren_depth);
        if (!q)
            return ZONE_ERR_SYNTAX;
        if (q >= end)
            break;
        p = q;
        
        if (paren_depth == 0 && (uint8_t)*p == '\n') {
            zone_to_space(p);
            p++;
            break;
        }
        if (paren_depth == 0 && (uint8_t)*p == '\r') {
            zone_to_space(p); p++;
            if ((uint8_t)*p == '\n') {
                zone_to_space(p); p++;
            }
            break;
        }
        
        if (out->rrtoken_count >= ZONE_MAX_RRTOKENS)
            return ZONE_ERR_TOO_MANY_TOKENS;
        
        char *start = p;
        char *after;
        
        if ((uint8_t)*p == '"') {
            after = zone_scan_quoted(p);
            if (!after)
                return ZONE_ERR_UNTERM_QUOTE;
        } else {
            after = zone_scan_unquoted(p, end, paren_depth, find_special);
        }
        
        out->rrtokens[out->rrtoken_count].off = (uint32_t)(start - base);
        out->rrtokens[out->rrtoken_count].len = (uint32_t)(after - start);
        out->rrtoken_count++;
        
        p = after;
    }
    
    if (paren_depth != 0)
        return ZONE_ERR_UNBAL_PARENS;
    return ZONE_OK;
}

// ----------------------------- quick tests -----------------------------
//
// NOTE: To make this self-contained despite zone_rrtype_lookup being external,
// the tests only *assert tokenization structure* for known types if your
// zone_rrtype_lookup supports them; otherwise they'll still exercise syntax.
// If you want strict asserts on rrtype numbers, link a real lookup or provide
// a tiny test stub in your test build.

void dump_tokenized(const char *label, const char *rec, const struct zone_tokenized *z) {
  printf("== %s ==\n", label);
  printf("has_ttl=%u ttl=%u has_class=%u class=%u type=%u backend=%d\n",
         z->has_ttl, z->ttl_seconds, z->has_class, z->rrclass, z->rr_type->value,
         (int)zone_tokenizer_get_backend());
  printf("rrtokens=%u\n", z->rrtoken_count);
  for (uint32_t i = 0; i < z->rrtoken_count; i++) {
    uint32_t off = z->rrtokens[i].off, len = z->rrtokens[i].len;
    printf("  [%u] off=%u len=%u |", i, off, len);
    for (uint32_t j = 0; j < len; j++) putchar(rec[off + j]);
    printf("|\n");
  }
  printf("\n");
}
#define TEST_ASSERT(x) if (!(x)) {fprintf(stderr, "[-] %s\n", #x); return 1;}

static int _zone_tokenize_quicktest(int backend) {
  int rc;
  struct zone_tokenized z;

  // Exercise AUTO and forced modes (doesn't assert which one is picked, just that it runs).
  zone_tokenizer_init(backend);

  // 1) TTL + CLASS + TYPE + RRDATA + comment
  char t1[] = "  3600 IN A 192.0.2.1 ; comment here\n";
  rc = zone_tokenize(t1, sizeof(t1) - 1, &z);
  TEST_ASSERT(rc == 0);
  TEST_ASSERT(z.has_ttl && z.ttl_seconds == 3600);
  TEST_ASSERT(z.has_class && z.rrclass == ZONE_CLASS_IN);
  TEST_ASSERT(z.rrtoken_count == 1);
  //dump_tokenized("t1 TTL+CLASS+TYPE+comment", t1, &z);

  // 2) CLASS then TTL then TYPE; escaped space in RRDATA token
  char t2[] = "  IN 1h MX 10 ex\\ ample.com.\n";
  rc = zone_tokenize(t2, sizeof(t2) - 1, &z);
  TEST_ASSERT(rc == 0);
  TEST_ASSERT(z.has_ttl && z.ttl_seconds == 3600);
  TEST_ASSERT(z.has_class && z.rrclass == ZONE_CLASS_IN);
  TEST_ASSERT(z.rrtoken_count == 2);
  //dump_tokenized("t2 escaped space", t2, &z);

  // 3) Unknown TYPE via TYPEnnnn fallback must work without zone_rrtype_lookup knowing it.
  char t3[] = "  7200 IN TYPE65000 \\# 4 DEADBEEF\n";
  rc = zone_tokenize(t3, sizeof(t3) - 1, &z);
  TEST_ASSERT(rc == 0);
  TEST_ASSERT(z.rr_type->value == 65000);
  //dump_tokenized("t3 TYPEnnnn", t3, &z);

  // 4) Quoted string with spaces and escaped quote; comment after it
  char t4[] = "  IN TXT \"hello world \\\"quoted\\\"\" ; trailing comment\n";
  rc = zone_tokenize(t4, sizeof(t4) - 1, &z);
  TEST_ASSERT(rc == 0);
  TEST_ASSERT(z.rrtoken_count == 1);
  //dump_tokenized("t4 quoted+comment", t4, &z);

  // 5) Parentheses: multiline RRDATA; newline becomes whitespace; comment inside parens
  char t5[] =
    "  300 IN TXT ( \"part one\" \n"
    "              ; comment in parens\n"
    "              \"part two\" )\n";
  rc = zone_tokenize(t5, sizeof(t5) - 1, &z);
  TEST_ASSERT(rc == 0);
  TEST_ASSERT(z.has_ttl && z.ttl_seconds == 300);
  TEST_ASSERT(z.rrtoken_count == 2);
  //dump_tokenized("t5 parens+multiline+comment", t5, &z);

  // 6) CRLF inside parens acts as whitespace; outside ends record
  char t6[] = " IN TXT ( \"a\"\r\n \"b\" )\r\n";
  rc = zone_tokenize(t6, sizeof(t6) - 1, &z);
  TEST_ASSERT(rc == 0);
  TEST_ASSERT(z.rrtoken_count == 2);
  //dump_tokenized("t6 CRLF", t6, &z);

  // 7) Unterminated quote must error
  char t7[] = " IN TXT \"oops\n";
  rc = zone_tokenize(t7, sizeof(t7) - 1, &z);
  TEST_ASSERT(rc == ZONE_ERR_UNTERM_QUOTE);

  // 8) Unbalanced parens must error
  char t8[] = " IN TXT ( \"oops\"\n";
  rc = zone_tokenize(t8, sizeof(t8) - 1, &z);
  TEST_ASSERT(rc == ZONE_ERR_UNBAL_PARENS);

  // Now force SCALAR (ensures runtime override is exercised).
  //zone_tokenizer_set_backend(SIMD_SCALAR);
  char t9[] = "  IN 5m TYPE123 1 2 3\n";
  rc = zone_tokenize(t9, sizeof(t9) - 1, &z);
  TEST_ASSERT(rc == 0);
  TEST_ASSERT(z.rr_type->value == 123);
  //dump_tokenized("t9 forced scalar", t9, &z);

  //printf("zone_tokenize_quicktest: all tests passed.\n");
  return 0;
}

int zone_tokenize_quicktest(void) {
    int err = 0;
    
    err += _zone_tokenize_quicktest(SIMD_SCALAR);
    err += _zone_tokenize_quicktest(SIMD_SWAR);
    err += _zone_tokenize_quicktest(SIMD_AUTO);
    
    return (int)err;
}

