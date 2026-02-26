// SIMD: Find first occurrence of any of 5 special chars: ( ; \ " \n
#include "util-simd.h"
#include "zone-scan.h"
#include <string.h>

#if defined(SIMD_AVX2)
static size_t scan_avx2(const char *data, size_t i, size_t len) {
    const __m256i paren = _mm256_set1_epi8('(');
    const __m256i semi = _mm256_set1_epi8(';');
    const __m256i backslash = _mm256_set1_epi8('\\');
    const __m256i quote = _mm256_set1_epi8('"');
    const __m256i newline = _mm256_set1_epi8('\n');
    
    for (; i + 32 <= len; i += 32) {
        __m256i chunk = _mm256_loadu_si256((const __m256i*)(data + i));
        __m256i m1 = _mm256_cmpeq_epi8(chunk, paren);
        __m256i m2 = _mm256_cmpeq_epi8(chunk, semi);
        __m256i m3 = _mm256_cmpeq_epi8(chunk, backslash);
        __m256i m4 = _mm256_cmpeq_epi8(chunk, quote);
        __m256i m5 = _mm256_cmpeq_epi8(chunk, newline);
        
        __m256i combined = _mm256_or_si256(_mm256_or_si256(m1, m2),
                                           _mm256_or_si256(_mm256_or_si256(m3, m4), m5));
        
        int mask = _mm256_movemask_epi8(combined);
        if (mask) return i + __builtin_ctz(mask);
    }
    
    for (; i < len; i++) {
        char c = data[i];
        if (c == '(' || c == ';' || c == '\\' || c == '"' || c == '\n') return i;
    }
    return len;
}
#endif

#if defined(SIMD_SSE2)
static size_t scan_sse2(const char *data, size_t i, size_t len) {
    const __m128i paren = _mm_set1_epi8('(');
    const __m128i semi = _mm_set1_epi8(';');
    const __m128i backslash = _mm_set1_epi8('\\');
    const __m128i quote = _mm_set1_epi8('"');
    const __m128i newline = _mm_set1_epi8('\n');
    
    for (; i + 16 <= len; i += 16) {
        __m128i chunk = _mm_loadu_si128((const __m128i*)(data + i));
        __m128i m1 = _mm_cmpeq_epi8(chunk, paren);
        __m128i m2 = _mm_cmpeq_epi8(chunk, semi);
        __m128i m3 = _mm_cmpeq_epi8(chunk, backslash);
        __m128i m4 = _mm_cmpeq_epi8(chunk, quote);
        __m128i m5 = _mm_cmpeq_epi8(chunk, newline);
        
        __m128i combined = _mm_or_si128(_mm_or_si128(m1, m2),
                                        _mm_or_si128(_mm_or_si128(m3, m4), m5));
        
        int mask = _mm_movemask_epi8(combined);
        if (mask) return i + __builtin_ctz(mask);
    }
    
    for (; i < len; i++) {
        char c = data[i];
        if (c == '(' || c == ';' || c == '\\' || c == '"' || c == '\n') return i;
    }
    return len;
}
#endif

#if defined(SIMD_NEON)
static size_t scan_neon(const char *data, size_t i, size_t len) {
    const uint8x16_t paren = vdupq_n_u8('(');
    const uint8x16_t semi = vdupq_n_u8(';');
    const uint8x16_t backslash = vdupq_n_u8('\\');
    const uint8x16_t quote = vdupq_n_u8('"');
    const uint8x16_t newline = vdupq_n_u8('\n');
    
    for (; i + 16 <= len; i += 16) {
        uint8x16_t chunk = vld1q_u8((const uint8_t*)(data + i));
        uint8x16_t m1 = vceqq_u8(chunk, paren);
        uint8x16_t m2 = vceqq_u8(chunk, semi);
        uint8x16_t m3 = vceqq_u8(chunk, backslash);
        uint8x16_t m4 = vceqq_u8(chunk, quote);
        uint8x16_t m5 = vceqq_u8(chunk, newline);
        
        uint8x16_t combined = vorrq_u8(vorrq_u8(m1, m2), vorrq_u8(vorrq_u8(m3, m4), m5));
        
        uint64_t low = vgetq_lane_u64(vreinterpretq_u64_u8(combined), 0);
        uint64_t high = vgetq_lane_u64(vreinterpretq_u64_u8(combined), 1);
        
        if (low) {
            for (int j = 0; j < 8; j++) {
                char c = data[i + j];
                if (c == '(' || c == ';' || c == '\\' || c == '"' || c == '\n')
                    return i + j;
            }
        }
        if (high) {
            for (int j = 8; j < 16; j++) {
                char c = data[i + j];
                if (c == '(' || c == ';' || c == '\\' || c == '"' || c == '\n')
                    return i + j;
            }
        }
    }
    
    for (; i < len; i++) {
        char c = data[i];
        if (c == '(' || c == ';' || c == '\\' || c == '"' || c == '\n') return i;
    }
    return len;
}
#endif

static size_t scan_swar(const char *data, size_t i, size_t len) {
    for (; i + 8 <= len; i += 8) {
        uint64_t chunk;
        memcpy(&chunk, data + i, 8);
        
        uint64_t has_paren = chunk ^ 0x2828282828282828ULL;
        uint64_t has_semi = chunk ^ 0x3B3B3B3B3B3B3B3BULL;
        uint64_t has_backslash = chunk ^ 0x5C5C5C5C5C5C5C5CULL;
        uint64_t has_quote = chunk ^ 0x2222222222222222ULL;
        uint64_t has_newline = chunk ^ 0x0A0A0A0A0A0A0A0AULL;
        
        uint64_t detect = 0x8080808080808080ULL;
        uint64_t z1 = (has_paren - 0x0101010101010101ULL) & ~has_paren & detect;
        uint64_t z2 = (has_semi - 0x0101010101010101ULL) & ~has_semi & detect;
        uint64_t z3 = (has_backslash - 0x0101010101010101ULL) & ~has_backslash & detect;
        uint64_t z4 = (has_quote - 0x0101010101010101ULL) & ~has_quote & detect;
        uint64_t z5 = (has_newline - 0x0101010101010101ULL) & ~has_newline & detect;
        
        if (z1 | z2 | z3 | z4 | z5) {
            for (int j = 0; j < 8; j++) {
                char c = data[i + j];
                if (c == '(' || c == ';' || c == '\\' || c == '"' || c == '\n')
                    return i + j;
            }
        }
    }
    
    for (; i < len; i++) {
        char c = data[i];
        if (c == '(' || c == ';' || c == '\\' || c == '"' || c == '\n') return i;
    }
    return len;
}

static size_t scan_scalar(const char *data, size_t i, size_t len) {
    for (; i < len; i++) {
        char c = data[i];
        if (c == '(' || c == ';' || c == '\\' || c == '"' || c == '\n') return i;
    }
    return len;
}

#define scanner zone_scan_fast
size_t (*zone_scan_fast)(const char *data, size_t offset, size_t len) = scan_scalar;

void zone_scan_fast_init(simd_backend_t backend) {
    switch (backend) {
    case SIMD_AUTO:
        zone_scan_fast_init(simd_get_best());
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

int zone_scan_fast_quicktest(void) {
    static struct testcases {
        const char *data;
        size_t expected;
    } tests[] = {
        {"abc \naaa", 4},
        {"abcd\t\naaa", 5},
        {"abcde\naaaa", 5},
        {"abcdef\r\naaa", 7},
        {"abc\\ def\naaa", 3},
        {"abc ( def ) \naaa", 4},
        {"abc    ; comment ( ) \n def ) \naaa", 7},
        {0,0}
    };
    
    int err = 0;
    
    for (int i=0; tests[i].data; i++) {
        char buf[1024];
        size_t in_len = strlen(tests[i].data);
        memset(buf, '\n', sizeof(buf));
        memcpy(buf, tests[i].data, in_len);
        
        size_t out = zone_scan_fast(buf, 0, in_len);
        if (out != tests[i].expected) {
            fprintf(stderr, "[-] scan.fast(): test %d failed: \"%s\"\n", i, tests[i].data);
            err++;
        }
    }
    
    return err;
}

