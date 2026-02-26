#include "zone-parse.h"
#include "zone-atom.h"
#include "util-simd.h"

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/*
 * This is the slow function we'll call if we can't load the library
 */
static size_t tb64dec_default(const char *in, size_t inlen, unsigned char *out) {
  
    unsigned depth = 0;
    struct wire_record_t out2 = {0};
    out2.wire.buf = out;
    out2.wire.max = 1000;
    
    
    zone_atom_base64c(in, 0, inlen, &out2, &depth);
    return out2.wire.len;
}

/*
 * Pointers to the external functions in the Turbo-BASE64 library. We load
 * these dynamically, if the library is available in our path.
 */
static size_t (*tb64dec)(const char *in, size_t inlen, unsigned char *out) = tb64dec_default;
static unsigned (*cpuini)(unsigned cpuisa);
static char *(*cpustr)(unsigned cpuisa);




#if defined(_MSC_VER)
#  include <intrin.h>
#endif


/* ---- BASE64 validity ----
 * BASE64 chars: A-Z a-z 0-9 + / and padding '='
 */
static inline int is_b64_u8(uint8_t c) {
    return ((c >= (uint8_t)'A' && c <= (uint8_t)'Z') ||
            (c >= (uint8_t)'a' && c <= (uint8_t)'z') ||
            (c >= (uint8_t)'0' && c <= (uint8_t)'9') ||
            c == (uint8_t)'+' || c == (uint8_t)'/' || c == (uint8_t)'=');
}


/* ---------------- Scalar scanner ---------------- */
static size_t scan_scalar(const char *p)
{
    const uint8_t *s = (const uint8_t *)(const void *)p;
    size_t i = 0;

    /* Overread-safe by contract. */
    for (;;) {
        if (!is_b64_u8(s[i])) return i;
        i++;
    }
}
/* Scanner signature: returns number of consecutive BASE64 chars from p forward. */
typedef size_t (*scan_nobase_fn)(const char *p);
static scan_nobase_fn scanner = scan_scalar;


/* ---------------- SWAR scanner (lightweight) ----------------
 * This is a simple 8-byte chunked scanner; still branch-light, but not fancy.
 */
static size_t scan_swar(const char *p)
{
    const uint8_t *s = (const uint8_t *)(const void *)p;
    size_t i = 0;

    for (;;) {
        /* Unroll 8 bytes per iteration. */
        if (!is_b64_u8(s[i+0])) return i+0;
        if (!is_b64_u8(s[i+1])) return i+1;
        if (!is_b64_u8(s[i+2])) return i+2;
        if (!is_b64_u8(s[i+3])) return i+3;
        if (!is_b64_u8(s[i+4])) return i+4;
        if (!is_b64_u8(s[i+5])) return i+5;
        if (!is_b64_u8(s[i+6])) return i+6;
        if (!is_b64_u8(s[i+7])) return i+7;
        i += 8;
    }
}

#if defined(SIMD_SSE2) || defined(SIMD_SSE42) || defined(SIMD_AVX2) || defined(SIMD_AVX512)
#  include <immintrin.h>
#endif

/* ---- SSE2 helpers (unsigned range check) ---- */
#if defined(SIMD_SSE2) || defined(SIMD_SSE42)

static inline __m128i u8_in_range_sse2(__m128i v, uint8_t lo, uint8_t hi)
{
    const __m128i vlo = _mm_set1_epi8((char)lo);
    const __m128i vhi = _mm_set1_epi8((char)hi);

    /* ge = (max(v, lo) == v)  for unsigned bytes */
    const __m128i ge = _mm_cmpeq_epi8(_mm_max_epu8(v, vlo), v);
    /* le = (min(v, hi) == v) */
    const __m128i le = _mm_cmpeq_epi8(_mm_min_epu8(v, vhi), v);

    return _mm_and_si128(ge, le); /* 0xFF where in range */
}

static size_t scan_sse2_impl(const char *p)
{
    const uint8_t *s = (const uint8_t *)(const void *)p;
    size_t off = 0;

    const __m128i vplus  = _mm_set1_epi8('+');
    const __m128i vslash = _mm_set1_epi8('/');
    const __m128i veq    = _mm_set1_epi8('=');
    const __m128i vzero  = _mm_setzero_si128();

    for (;;) {
        const __m128i v = _mm_loadu_si128((const __m128i *)(const void *)(s + off));

        __m128i m = u8_in_range_sse2(v, (uint8_t)'A', (uint8_t)'Z');
        m = _mm_or_si128(m, u8_in_range_sse2(v, (uint8_t)'a', (uint8_t)'z'));
        m = _mm_or_si128(m, u8_in_range_sse2(v, (uint8_t)'0', (uint8_t)'9'));
        m = _mm_or_si128(m, _mm_cmpeq_epi8(v, vplus));
        m = _mm_or_si128(m, _mm_cmpeq_epi8(v, vslash));
        m = _mm_or_si128(m, _mm_cmpeq_epi8(v, veq));

        /* invalid bytes are those with m == 0 */
        const __m128i invbytes = _mm_cmpeq_epi8(m, vzero);
        const unsigned invmask = (unsigned)_mm_movemask_epi8(invbytes);

        if (invmask) {
            return off + (size_t)ctz32(invmask);
        }
        off += 16;
    }
}

static size_t scan_sse2(const char *p)  { return scan_sse2_impl(p); }
static size_t scan_sse42(const char *p) { return scan_sse2_impl(p); }

#endif /* SIMD_SSE2 || SIMD_SSE42 */

/* ---- AVX2 ---- */
#if defined(SIMD_AVX2)

static inline __m256i u8_in_range_avx2(__m256i v, uint8_t lo, uint8_t hi)
{
    const __m256i vlo = _mm256_set1_epi8((char)lo);
    const __m256i vhi = _mm256_set1_epi8((char)hi);

    const __m256i ge = _mm256_cmpeq_epi8(_mm256_max_epu8(v, vlo), v);
    const __m256i le = _mm256_cmpeq_epi8(_mm256_min_epu8(v, vhi), v);
    return _mm256_and_si256(ge, le);
}

static size_t scan_avx2(const char *p)
{
    const uint8_t *s = (const uint8_t *)(const void *)p;
    size_t off = 0;

    const __m256i vplus  = _mm256_set1_epi8('+');
    const __m256i vslash = _mm256_set1_epi8('/');
    const __m256i veq    = _mm256_set1_epi8('=');
    const __m256i vzero  = _mm256_setzero_si256();

    for (;;) {
        const __m256i v = _mm256_loadu_si256((const __m256i *)(const void *)(s + off));

        __m256i m = u8_in_range_avx2(v, (uint8_t)'A', (uint8_t)'Z');
        m = _mm256_or_si256(m, u8_in_range_avx2(v, (uint8_t)'a', (uint8_t)'z'));
        m = _mm256_or_si256(m, u8_in_range_avx2(v, (uint8_t)'0', (uint8_t)'9'));
        m = _mm256_or_si256(m, _mm256_cmpeq_epi8(v, vplus));
        m = _mm256_or_si256(m, _mm256_cmpeq_epi8(v, vslash));
        m = _mm256_or_si256(m, _mm256_cmpeq_epi8(v, veq));

        const __m256i invbytes = _mm256_cmpeq_epi8(m, vzero);
        const unsigned invmask = (unsigned)_mm256_movemask_epi8(invbytes);

        if (invmask) {
            return off + (size_t)ctz32(invmask);
        }
        off += 32;
    }
}

#endif /* SIMD_AVX2 */

/* ---- AVX-512 ---- */
#if defined(SIMD_AVX512)

static inline __mmask64 u8_in_range_avx512(__m512i v, uint8_t lo, uint8_t hi)
{
    /* unsigned compares are available as mask ops */
    const __m512i vlo = _mm512_set1_epi8((char)lo);
    const __m512i vhi = _mm512_set1_epi8((char)hi);
    const __mmask64 ge = _mm512_cmp_epu8_mask(v, vlo, _MM_CMPINT_GE);
    const __mmask64 le = _mm512_cmp_epu8_mask(v, vhi, _MM_CMPINT_LE);
    return (ge & le);
}

static size_t scan_avx512(const char *p)
{
    const uint8_t *s = (const uint8_t *)(const void *)p;
    size_t off = 0;

    const __m512i vplus  = _mm512_set1_epi8('+');
    const __m512i vslash = _mm512_set1_epi8('/');
    const __m512i veq    = _mm512_set1_epi8('=');

    for (;;) {
        const __m512i v = _mm512_loadu_si512((const void *)(s + off));

        __mmask64 ok = u8_in_range_avx512(v, (uint8_t)'A', (uint8_t)'Z');
        ok |= u8_in_range_avx512(v, (uint8_t)'a', (uint8_t)'z');
        ok |= u8_in_range_avx512(v, (uint8_t)'0', (uint8_t)'9');
        ok |= _mm512_cmpeq_epi8_mask(v, vplus);
        ok |= _mm512_cmpeq_epi8_mask(v, vslash);
        ok |= _mm512_cmpeq_epi8_mask(v, veq);

        const __mmask64 bad = ~ok; /* bits set where invalid */
        if (bad) {
            return off + (size_t)ctz64((uint64_t)bad);
        }
        off += 64;
    }
}

#endif /* SIMD_AVX512 */

#if defined(SIMD_NEON) || defined(SIMD_SVE2)
#  include <arm_neon.h>
#endif

/* ---- NEON (AArch64) ---- */
#if defined(SIMD_NEON)

static inline uint32_t neon_movemask_u8(uint8x16_t vff00)
{
    /* vff00 has 0xFF in lanes of interest. Return 16-bit mask in low bits. */
    uint8x16_t b = vshrq_n_u8(vff00, 7);
    const int8x8_t shifts = (int8x8_t){0,1,2,3,4,5,6,7};
    uint8x8_t lo = vshl_u8(vget_low_u8(b), shifts);
    uint8x8_t hi = vshl_u8(vget_high_u8(b), shifts);
    return (uint32_t)vaddv_u8(lo) | ((uint32_t)vaddv_u8(hi) << 8);
}

static inline uint8x16_t neon_in_range(uint8x16_t v, uint8_t lo, uint8_t hi)
{
    const uint8x16_t vlo = vdupq_n_u8(lo);
    const uint8x16_t vhi = vdupq_n_u8(hi);
    const uint8x16_t ge = vcgeq_u8(v, vlo);
    const uint8x16_t le = vcleq_u8(v, vhi);
    return vandq_u8(ge, le); /* 0xFF where ok */
}

static size_t scan_neon(const char *p)
{
    const uint8_t *s = (const uint8_t *)(const void *)p;
    size_t off = 0;

    const uint8x16_t vplus  = vdupq_n_u8((uint8_t)'+');
    const uint8x16_t vslash = vdupq_n_u8((uint8_t)'/');
    const uint8x16_t veq    = vdupq_n_u8((uint8_t)'=');

    for (;;) {
        const uint8x16_t v = vld1q_u8(s + off);

        uint8x16_t ok = neon_in_range(v, (uint8_t)'A', (uint8_t)'Z');
        ok = vorrq_u8(ok, neon_in_range(v, (uint8_t)'a', (uint8_t)'z'));
        ok = vorrq_u8(ok, neon_in_range(v, (uint8_t)'0', (uint8_t)'9'));
        ok = vorrq_u8(ok, vceqq_u8(v, vplus));
        ok = vorrq_u8(ok, vceqq_u8(v, vslash));
        ok = vorrq_u8(ok, vceqq_u8(v, veq));

        /* invalid lanes => ok == 0; make mask of invalid */
        const uint8x16_t bad = vceqq_u8(ok, vdupq_n_u8(0));
        const uint32_t badmask = neon_movemask_u8(bad);

        if (badmask) {
            return off + (size_t)ctz32(badmask);
        }
        off += 16;
    }
}

#endif /* SIMD_NEON */

/* ---- SVE2 (portable but simple): load vector, store, scalar locate first invalid ---- */
#if defined(SIMD_SVE2)
#  include <arm_sve.h>

static size_t scan_sve2(const char *p)
{
    const uint8_t *s = (const uint8_t *)(const void *)p;
    size_t off = 0;

    for (;;) {
        svbool_t pg = svptrue_b8();
        svuint8_t v = svld1_u8(pg, s + off);

        /* Build valid predicate (byte-wise). */
        svbool_t ok = svand_b_z(pg,
            svcmpge_u8(pg, v, svdup_u8((uint8_t)'A')),
            svcmple_u8(pg, v, svdup_u8((uint8_t)'Z')));

        svbool_t t;

        t = svand_b_z(pg,
            svcmpge_u8(pg, v, svdup_u8((uint8_t)'a')),
            svcmple_u8(pg, v, svdup_u8((uint8_t)'z')));
        ok = svorr_b_z(pg, ok, t);

        t = svand_b_z(pg,
            svcmpge_u8(pg, v, svdup_u8((uint8_t)'0')),
            svcmple_u8(pg, v, svdup_u8((uint8_t)'9')));
        ok = svorr_b_z(pg, ok, t);

        ok = svorr_b_z(pg, ok, svcmpeq_u8(pg, v, svdup_u8((uint8_t)'+')));
        ok = svorr_b_z(pg, ok, svcmpeq_u8(pg, v, svdup_u8((uint8_t)'/')));
        ok = svorr_b_z(pg, ok, svcmpeq_u8(pg, v, svdup_u8((uint8_t)'=')));

        svbool_t bad = svnot_b_z(pg, ok);

        if (svptest_any(pg, bad)) {
            /* Store and find exact index (still fast enough, and correct). */
            const size_t vl = svcntb();
            uint8_t tmp[256];
            /* vl can exceed 256 on some targets, but SVE2 in practice is bounded;
               if you want strict, replace with alloca(vl). */
            if (vl > sizeof(tmp)) {
                /* fallback if some huge VL */
                return off + scan_scalar((const char *)(const void *)(s + off));
            }
            svst1_u8(pg, tmp, v);
            for (size_t i = 0; i < vl; i++) {
                if (!is_b64_u8(tmp[i])) return off + i;
            }
            /* should not happen, but be safe */
            off += vl;
        } else {
            off += svcntb();
        }
    }
}

#endif /* SIMD_SVE2 */

/* ---- RISC-V V: placeholder scalar-chunk fallback under SIMD_RISCVV ---- */
#if defined(SIMD_RISCVV)
static size_t scan_riscvv(const char *p)
{
    /* If you have <riscv_vector.h> and want a real vector path, drop it in here.
       This is still correct and keeps backend wiring consistent. */
    return scan_swar(p);
}
#endif

/* ---------------- Runtime backend selection ---------------- */

void zone_scan_nobase_init(simd_backend_t backend)
{
    switch (backend) {
    case SIMD_AUTO:
        zone_scan_nobase_init(simd_get_best());
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

/* ---------------- Main wrapper ---------------- */

size_t zone_atom_base64c(const char *data, size_t cursor, size_t max,
                         struct wire_record_t *out, unsigned *depth)
{
    /* Carry 1..3 chars across whitespace. */
    char carry_buf[4];
    size_t carry_length = 0;

    for (;;) {
        
        /*
         * Scan forward measuring the `length` of the next BASE64 string.
         */
        size_t length = scanner(data + cursor);
        
        /*
         * Process leftover characters from the previous large BASE64
         * strin, completing a 4-character group by pulling from the next run.
         */
        if (carry_length) {
            const size_t need = 4 - carry_length;
            
            /* Boundary: we still don't have enough characters, so loop
             * yet again. */
            if (length < need) {
                memcpy(carry_buf + carry_length, data + cursor, length);
                carry_length += length;
                cursor += length;
                goto again;
            }

            /* Complete the quartet */
            memcpy(carry_buf + carry_length, data + cursor, need);
            cursor += need; /* move our cursor forward */
            length -= need; /* reduce the length of the next string.*/

            /* Call the parser on our little bit */
            const size_t count = tb64dec(carry_buf, 4, out->wire.buf + out->wire.len);
            out->wire.len += count;
            if (count == 0)
                return PARSE_ERR(1, cursor, max, out);
            
            
            /* empty our carry buffer */
            carry_length = 0;
        }

        /*
         * See if there will be any leftovers after we parse the next
         * chunk.
         */
        const size_t aligned = length & ~(size_t)3u;
        const size_t leftovers = length - aligned;
        
        /*
         * Do the parsing of this even/aligned chunk, which is guaranteed
         * to have a multiple of 4 number of characters.
         */
        if (aligned) {
            size_t count = tb64dec(data + cursor, aligned, out->wire.buf + out->wire.len);
            out->wire.len += count;
            cursor += aligned;
            if (count == 0)
                return PARSE_ERR(1, cursor, max, out);
        }
        
        /*
         * If there were any leftover characters, save them for
         * parsing before the next chunk.
         */
        if (leftovers) {
            memcpy(carry_buf, data + cursor, leftovers);
            carry_length = leftovers;
            cursor += leftovers;
        }


        
    again:
        /*
         * Consume any space after the BASE64 string. This may be
         * things like parentheses and comments, as well as
         * just normal space */
        cursor = zone_parse_space(data, cursor, max, out, depth);

        /*
         * See if we've reached the end of the record.
         */
        const char c = data[cursor];
        if (c == '\r' || c == '\n') {
            /* Boundary: dangling characters at end of line */
            if (carry_length)
                return PARSE_ERR(1, cursor, max, out);
            return cursor;
        }
    }

    
}
struct test_case {
    const char *b64str;
    unsigned char expected[21];
};

int zone_atom_base64c_quicktest(void) {
    struct test_case tests[] = {
        // Test 1: "abc" -> [0x61, 0x62, 0x63, 0, 0, 0, 0, 0, 0]
        { "YWJj \n", {0x61, 0x62, 0x63, 0, 0, 0, 0, 0, 0} },
        
        // Test 2: All zeros
        { "AAAAAAAAAAA=\r\n", {0, 0, 0, 0, 0, 0, 0, 0, 0} },
        
        // Test 3: Max byte values (255,254,...,247)
        { "//////8=\n", {0xFF, 0xFf, 0xFf, 0xFf, 0xFf, 0x00, 0x00, 0x00, 0x00} },
        
        // Test 4: Mixed ASCII printable
        { "S(G)VsbG8gV29ybGQ=\n", {0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x57, 0x6F, 0x72, 0x6c, 0x64} },
        { "SGVsbG 8gV29ybGQ=\n", {0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x57, 0x6F, 0x72, 0x6c, 0x64} },
        { "S G V s b G 8gV29ybGQ= \n", {0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x57, 0x6F, 0x72, 0x6c, 0x64} },

        // Test 5: Single bytes with padding variations
        { "AAECAwQFBg==\n", {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08} },
        
        // Test 6: Repeating pattern
        { "QUJDREVG\n", {0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0, 0, 0} },
        
        // Test 7: Edge case - 9 bytes exactly, ends mid-group
        { "VGhpcyBpcyBh\n", {0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x61} },
    };
    
    const int num_tests = sizeof(tests) / sizeof(tests[0]);
    int failed = 0;
    
    for (int i = 0; i < num_tests; i++) {
        const unsigned char *expected = tests[i].expected;
        const char *data = tests[i].b64str;
        size_t max = strlen(data);
        unsigned char wirebuf[4096];
        wire_record_t out = {0};
        out.wire.buf = wirebuf;
        unsigned depth = 0;
        
        /*
         * Call the tested function
         */
        size_t cursor = zone_atom_base64c(data, 0, max, &out, &depth);
        
        if (cursor >= max || out.err.code) {
            fprintf(stderr, "[-] atom.base64c: #%d error\n", i);
            failed++;
            continue;
        }
        
        if (memcmp(out.wire.buf, expected, out.wire.len) != 0) {
            fprintf(stderr, "[-] atom.base64c: #%d (tb64dec): output mismatch\n", i);
            int i;
            for (i=0; i<out.wire.len; i++) {
                printf("%02x ", out.wire.buf[i]);
            }
            printf("\n");
            for (i=0; i<cursor; i++) {
                printf("%02x ", expected[i]);
            }
            printf("\n");
            
            failed++;
        }
    }
    
    if (failed == 0) {
        fprintf(stderr, "[+] atom.base64c: all %d tests passed!\n", num_tests);
    } else {
        fprintf(stderr, "[-] atom.base64c: %d out of %d tests failed\n", failed, num_tests);
        return 1;
    }
    
    return 0;
}

#include <dlfcn.h>

void zone_atom_base64c_init(int backend) {
    /* Set our own backend. This may differ from the backend that
     * the Turbo-BASE64 library is using. */
    zone_scan_nobase_init(backend);

    void *h = dlopen("libtb64.so", RTLD_NOW | RTLD_NODELETE);
    if (h == NULL) {
        perror("libtb64.so");
        fprintf(stderr, "[-] load Turbo-BASE64\n");

    } else {
        int err = 0;
        tb64dec = dlsym(h, "tb64dec");
        if (tb64dec == NULL) {
            perror("tb64dec()");
            err |= 1;
        }

        cpuini = dlsym(h, "cpuini");
        if (cpuini == NULL) {
            perror("cpuini()");
            err |= 1;
        }
        
        cpustr = dlsym(h, "cpustr");
        if (cpustr == NULL) {
            perror("cpustr()");
            err |= 1;
        }

        fprintf(stderr, "[+] load Turbo-BASE64\n");
    }

}
