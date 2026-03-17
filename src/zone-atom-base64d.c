/*
    Calls external library to do the actual BASE64 conversion.
 
    Uses SIMD scanner to tokenize the input, to find the lengths
    of the substrings.
 */
#include "zone-parse.h"
#include "zone-atom.h"
#include "util-simd.h"
#include "util-base64.h"
#include "zone-parse-token.h"

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
 * This is the slow function we'll call if we can't load the library.
 * It's located in util-base64.c. I say "slow" but it appears roughly
 * as fast as SIMD.
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

/**
 * When we use zonefile characters like (parens) and ;comments, the
 * BASE64 decoder will signal a failure. We need to switch from
 * a "happy-path" decoding to a "slow-path", where we handle
 * such characters, stripping them out of the tokens, and doing
 * parens depth handling. This is called only briefly, before going back
 * onto the "happy-path".
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

size_t zone_atom_base64d(const char *data, size_t cursor, size_t max,
                         struct wire_record_t *out, unsigned *depth) {
    /* SIMD pre-scan separating spaces and tokens  */
    parsetokens_t tokens = {0};

    for (;;) {
        /* Find the length of the BASE64 substring */
        size_t length = parse_token_length(data, cursor, &tokens);
        
        /* If it's not evenly aligned, then go to slow path*/
        if (length & 0x3)
            break;
        
        /* Decode it */
        size_t count = tb64dec(data + cursor, length, out->wire.buf + out->wire.len);
        
        /* If it failed for any reason, go to slow path */
        if (count == 0)
            break;
        else {
            cursor += length;
            out->wire.len += count;
        }

        /* now skip trailing space*/
        cursor += parse_space_length(data, cursor, &tokens);
        
        /*
         * See if we've reached the end of the record.
         */
        const char c = data[cursor];
        if (c == '\r' || c == '\n') {
            if (c == '\r')
                cursor++;
            return cursor;
        }
    }

    return zone_atom_base64b(data, cursor, max, out, depth);
}
struct test_case {
    const char *b64str;
    unsigned char expected[21];
};

int zone_atom_base64d_quicktest(void) {
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
        size_t cursor = zone_atom_base64d(data, 0, max, &out, &depth);
        
        if (cursor >= max || out.err.code) {
            fprintf(stderr, "[-] atom.base64d: #%d error\n", i);
            failed++;
            continue;
        }
        
        if (memcmp(out.wire.buf, expected, out.wire.len) != 0) {
            fprintf(stderr, "[-] atom.base64d: #%d (tb64dec): output mismatch\n", i);
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
        ;//fprintf(stderr, "[+] atom.base64d: all %d tests passed!\n", num_tests);
    } else {
        fprintf(stderr, "[-] atom.base64d: %d out of %d tests failed\n", failed, num_tests);
        return 1;
    }
    
    return 0;
}


void zone_atom_base64d_init(int backend) {
    /* Set our own backend. This may differ from the backend that
     * the Turbo-BASE64 library is using. */
    parse_tokens_init(backend);

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
            perror("tb64v128dec()");
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
