#include "zone-parse.h"
#include "zone-atom.h"
#include "util-simd.h"
#include "util-base64.h"

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifdef _WIN32
typedef void* HMODULE;
typedef const char* LPCSTR;
__declspec(dllimport) HMODULE __stdcall LoadLibraryA(LPCSTR);
__declspec(dllimport) void* __stdcall GetProcAddress(HMODULE, LPCSTR);
__declspec(dllimport) int __stdcall FreeLibrary(HMODULE); 
#else
#include <dlfcn.h>
#endif


/*
 * This is the slow function we'll call if we can't load the library
 */
static size_t tb64dec_default(const char *src, size_t inlen, unsigned char *out) {
    size_t outlen = 0;
    int is_good = base64_decode(src, inlen, out, &outlen);
    if (is_good && outlen)
        return outlen;
    else
        return 0;
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

static inline int is_ws4(uint8_t c) {
    return (c == (uint8_t)' '  ||
            c == (uint8_t)'\t' ||
            c == (uint8_t)'\r' ||
            c == (uint8_t)'\n');
}

static size_t scan_scalar(const char *p)
{
    const uint8_t *s = (const uint8_t *)(const void *)p;
    size_t i = 0;
    for (;;) {
        if (is_ws4(s[i])) return i;
        i++;
    }
}

static size_t scan_swar(const char *p)
{
    const uint8_t *s = (const uint8_t *)(const void *)p;
    size_t i = 0;
    for (;;) {
        if (is_ws4(s[i+0])) return i+0;
        if (is_ws4(s[i+1])) return i+1;
        if (is_ws4(s[i+2])) return i+2;
        if (is_ws4(s[i+3])) return i+3;
        if (is_ws4(s[i+4])) return i+4;
        if (is_ws4(s[i+5])) return i+5;
        if (is_ws4(s[i+6])) return i+6;
        if (is_ws4(s[i+7])) return i+7;
        i += 8;
    }
}/* Scanner signature: returns number of consecutive BASE64 chars from p forward. */
typedef size_t (*scan_nobase_fn)(const char *p);
static scan_nobase_fn scanner = scan_scalar;




#if defined(SIMD_SSE2) || defined(SIMD_SSE42) || defined(SIMD_AVX2) || defined(SIMD_AVX512)
#  include <immintrin.h>
#endif

/* ---- SSE2 helpers (unsigned range check) ---- */
#if defined(SIMD_SSE2) || defined(SIMD_SSE42)

static size_t scan_sse2_impl(const char *p)
{
    const uint8_t *s = (const uint8_t *)(const void *)p;
    size_t off = 0;

    const __m128i vsp  = _mm_set1_epi8(' ');
    const __m128i vtab = _mm_set1_epi8('\t');
    const __m128i vcr  = _mm_set1_epi8('\r');
    const __m128i vnl  = _mm_set1_epi8('\n');

    for (;;) {
        const __m128i v = _mm_loadu_si128((const __m128i *)(const void *)(s + off));

        __m128i m = _mm_cmpeq_epi8(v, vsp);
        m = _mm_or_si128(m, _mm_cmpeq_epi8(v, vtab));
        m = _mm_or_si128(m, _mm_cmpeq_epi8(v, vcr));
        m = _mm_or_si128(m, _mm_cmpeq_epi8(v, vnl));

        /* movemask has 1s where whitespace matched */
        const unsigned wmask = (unsigned)_mm_movemask_epi8(m);
        if (wmask) return off + (size_t)ctz32(wmask);

        off += 16;
    }
}

static size_t scan_sse2(const char *p)  { return scan_sse2_impl(p); }
static size_t scan_sse42(const char *p) { return scan_sse2_impl(p); }

#endif /* SIMD_SSE2 || SIMD_SSE42 */

/* ---- AVX2 ---- */
#if defined(SIMD_AVX2)

static size_t scan_avx2(const char *p)
{
    const uint8_t *s = (const uint8_t *)(const void *)p;
    size_t off = 0;

    const __m256i vsp  = _mm256_set1_epi8(' ');
    const __m256i vtab = _mm256_set1_epi8('\t');
    const __m256i vcr  = _mm256_set1_epi8('\r');
    const __m256i vnl  = _mm256_set1_epi8('\n');

    for (;;) {
        const __m256i v = _mm256_loadu_si256((const __m256i *)(const void *)(s + off));

        __m256i m = _mm256_cmpeq_epi8(v, vsp);
        m = _mm256_or_si256(m, _mm256_cmpeq_epi8(v, vtab));
        m = _mm256_or_si256(m, _mm256_cmpeq_epi8(v, vcr));
        m = _mm256_or_si256(m, _mm256_cmpeq_epi8(v, vnl));

        const unsigned wmask = (unsigned)_mm256_movemask_epi8(m);
        if (wmask) return off + (size_t)ctz32(wmask);

        off += 32;
    }
}
#endif /* SIMD_AVX2 */

/* ---- AVX-512 ---- */
#if defined(SIMD_AVX512)


static size_t scan_avx512(const char *p)
{
    const uint8_t *s = (const uint8_t *)(const void *)p;
    size_t off = 0;

    const __m512i vsp  = _mm512_set1_epi8(' ');
    const __m512i vtab = _mm512_set1_epi8('\t');
    const __m512i vcr  = _mm512_set1_epi8('\r');
    const __m512i vnl  = _mm512_set1_epi8('\n');

    for (;;) {
        const __m512i v = _mm512_loadu_si512((const void *)(s + off));

        __mmask64 m = _mm512_cmpeq_epi8_mask(v, vsp);
        m |= _mm512_cmpeq_epi8_mask(v, vtab);
        m |= _mm512_cmpeq_epi8_mask(v, vcr);
        m |= _mm512_cmpeq_epi8_mask(v, vnl);

        if (m) return off + (size_t)ctz64((uint64_t)m);

        off += 64;
    }
}

#endif /* SIMD_AVX512 */

#if defined(SIMD_NEON) || defined(SIMD_SVE2)
#  include <arm_neon.h>
#endif

/* ---- NEON (AArch64) ---- */
#if defined(SIMD_NEON)
#  include <arm_neon.h>

static inline uint32_t neon_movemask_u8(uint8x16_t vff00)
{
    uint8x16_t b = vshrq_n_u8(vff00, 7);
    const int8x8_t shifts = (int8x8_t){0,1,2,3,4,5,6,7};
    uint8x8_t lo = vshl_u8(vget_low_u8(b), shifts);
    uint8x8_t hi = vshl_u8(vget_high_u8(b), shifts);
    return (uint32_t)vaddv_u8(lo) | ((uint32_t)vaddv_u8(hi) << 8);
}

static size_t scan_neon(const char *p)
{
    const uint8_t *s = (const uint8_t *)(const void *)p;
    size_t off = 0;

    const uint8x16_t vsp  = vdupq_n_u8((uint8_t)' ');
    const uint8x16_t vtab = vdupq_n_u8((uint8_t)'\t');
    const uint8x16_t vcr  = vdupq_n_u8((uint8_t)'\r');
    const uint8x16_t vnl  = vdupq_n_u8((uint8_t)'\n');

    for (;;) {
        const uint8x16_t v = vld1q_u8(s + off);

        uint8x16_t m = vceqq_u8(v, vsp);
        m = vorrq_u8(m, vceqq_u8(v, vtab));
        m = vorrq_u8(m, vceqq_u8(v, vcr));
        m = vorrq_u8(m, vceqq_u8(v, vnl));

        const uint32_t wmask = neon_movemask_u8(m);
        if (wmask) return off + (size_t)ctz32(wmask);

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

        svbool_t m = svcmpeq_u8(pg, v, svdup_u8((uint8_t)' '));
        m = svorr_b_z(pg, m, svcmpeq_u8(pg, v, svdup_u8((uint8_t)'\t')));
        m = svorr_b_z(pg, m, svcmpeq_u8(pg, v, svdup_u8((uint8_t)'\r')));
        m = svorr_b_z(pg, m, svcmpeq_u8(pg, v, svdup_u8((uint8_t)'\n')));

        if (svptest_any(pg, m)) {
            /* Find first whitespace lane. */
            const size_t vl = svcntb();
            /* Prefer alloca for arbitrary VL. */
#if defined(_MSC_VER)
            uint8_t *tmp = (uint8_t *)_alloca(vl);
#else
            uint8_t *tmp = (uint8_t *)__builtin_alloca(vl);
#endif
            svst1_u8(pg, tmp, v);
            for (size_t i = 0; i < vl; i++) {
                if (is_ws4(tmp[i])) return off + i;
            }
        }

        off += svcntb();
    }
}

#endif

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

static void zone_scan_nobase_init(simd_backend_t backend)
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

/**
 * Scan forward for a space-equiv character like (); that is corrupting
 * a BASE64 decode, so we can shorten the string, decode it, then
 * try again.
 */
static size_t
find_space_equiv(const char *data, size_t max) {
    for (size_t i = 0; i < max; i++) {
        char c = data[i];
        if (c == '(' || c == ')' || c == ';')
            return i;
    }
    return max;
}

/* ---------------- Main wrapper ---------------- */

size_t zone_atom_base64c(const char *data, size_t cursor, size_t max,
                         struct wire_record_t *out, unsigned *depth)
{
    /* Carry 1..3 chars across whitespace. */
    char carry_buf[4] = { 0, 0, 0, 0 };
    size_t carry_length = 0;

    for (;;) {
        
        /*
         * Scan forward measuring the `length` of the next BASE64 string.
         */
        size_t length = scanner(data + cursor);
        
    retry:
        /*
         * Process leftover characters from the previous large BASE64
         * strin, completing a 4-character group by pulling from the next run.
         */
        if (carry_length) {
            
            /*
             * Save off existing state in case we need to retry
             */
            char carry2[4];
            size_t carry2_length = carry_length;
            memcpy(carry2, carry_buf, 4);
            
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
            
            /* Call the parser on our little bit */
            const size_t count = tb64dec(carry_buf, 4, out->wire.buf + out->wire.len);
            out->wire.len += count;
            if (count == 0) {
                size_t length2 = find_space_equiv(data + cursor, length);
                if (length2 < length) {
                    /* we have (parens) or ;comment and need to retry */
                    length = length2;
                    carry_length = carry2_length;
                    memcpy(carry_buf, carry2, 4);
                    goto retry;
                } else
                    return PARSE_ERR(1, cursor, max, out);
            }
            
            cursor += need; /* move our cursor forward */
            length -= need; /* reduce the length of the next string.*/

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
            if (count == 0) {
                size_t length2 = find_space_equiv(data + cursor, length);
                if (length2 < length) {
                    /* we have (parens) or ;comment and need to retry */
                    length = length2;
                    goto retry;
                } else
                    return PARSE_ERR(1, cursor, max, out);
            }
            out->wire.len += count;
            cursor += aligned;
                
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
        ; //fprintf(stderr, "[+] atom.base64c: all %d tests passed!\n", num_tests);
    } else {
        fprintf(stderr, "[-] atom.base64c: %d out of %d tests failed\n", failed, num_tests);
        return 1;
    }
    
    return 0;
}


void zone_atom_base64c_init(int backend) {
    /* Set our own backend. This may differ from the backend that
     * the Turbo-BASE64 library is using. */
    zone_scan_nobase_init(backend);

#ifdef _WIN32
#else
    void *h = dlopen("libtb64.so", RTLD_NOW | RTLD_NODELETE);
    if (h == NULL) {
        perror("libtb64.so");
        fprintf(stderr, "[-] failed to load Turbo-BASE64\n");

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

        fprintf(stderr, "[+] loaded Turbo-BASE64\n");
    }
#endif

}
