
#include "zone-parse.h"
#include "zone-atom.h"
#include "util-base64.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <stddef.h>
#include <stdint.h>

/*
 * 1 for: '(' ')' ';' '\r' '\n' ' ' '\t'
 * 0 for everything else.
 */

static const uint8_t zone_special_table[256] = {
/* 0x00–0x0F */
0,0,0,0,0,0,0,0,0,1,1,0,0,1,0,0,
/* 0x10–0x1F */
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
/* 0x20–0x2F */
1,0,0,0,0,0,0,0,1,1,0,0,0,0,0,0,
/* 0x30–0x3F */
0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,
/* 0x40–0x4F */
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
/* 0x50–0x5F */
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
/* 0x60–0x6F */
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
/* 0x70–0x7F */
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
/* 0x80–0x8F */
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
/* 0x90–0x9F */
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
/* 0xA0–0xAF */
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
/* 0xB0–0xBF */
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
/* 0xC0–0xCF */
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
/* 0xD0–0xDF */
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
/* 0xE0–0xEF */
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
/* 0xF0–0xFF */
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
};

static size_t
find_special(const char *data, size_t cursor, size_t max) {
    (void)max;
    const unsigned char *p = (const unsigned char *)data + cursor;
    size_t i = 0;

    while (!zone_special_table[p[i]])
        i++;

    return i;
}

static size_t tb64dec_default(const char *src, size_t inlen, unsigned char *out) {
    size_t outlen = 0;
    int is_good = base64_decode(src, inlen, out, &outlen);
    if (is_good && outlen)
        return outlen;
    else
        return 0;
}


size_t zone_atom_base64b(const char *data, size_t cursor, size_t max,
                         struct wire_record_t *out, unsigned *depth)
{
    /* Carry 1..3 chars across whitespace. */
    char carry_buf[4];
    size_t carry_length = 0;

    for (;;) {
        
        /*
         * Scan forward measuring the `length` of the next BASE64 string.
         */
        size_t length = find_special(data, cursor, max);
        
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
            const size_t count = tb64dec_default(carry_buf, 4, out->wire.buf + out->wire.len);
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
            size_t count = tb64dec_default(data + cursor, aligned, out->wire.buf + out->wire.len);
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
        cursor = zone_slow_space(data, cursor, max, out, depth);

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
/* -------------------------------------------------------------------------- */
/* Quicktest                                                                   */
/* -------------------------------------------------------------------------- */

struct test_case {
    const char *b64str;
    unsigned char expected[21];
};

int zone_atom_base64b_quicktest(void) {
    struct test_case tests[] = {
        // Test 3: Max byte values (255,254,...,247)
        { "//////8=\n", {0xFF, 0xFf, 0xFf, 0xFf, 0xFf, 0x00, 0x00, 0x00, 0x00} },
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
        out.wire.max = 2048;
        unsigned depth = 0;
        
        /*
         * Call the tested function
         */
        size_t cursor = zone_atom_base64b(data, 0, max, &out, &depth);
        
        if (cursor >= max || out.err.code) {
            fprintf(stderr, "[-] atom.base64b: #%d error\n", i);
            failed++;
            continue;
        }
        
        if (memcmp(out.wire.buf, expected, out.wire.len) != 0) {
            fprintf(stderr, "[-] atom.base64b: #%d (tb64dec): output mismatch\n", i);
            size_t j;
            for (j=0; j<out.wire.len; j++) {
                printf("%02x ", out.wire.buf[j]);
            }
            printf("\n");
            for (j=0; j<cursor; j++) {
                printf("%02x ", expected[j]);
            }
            printf("\n");
            
            failed++;
        }
    }
    
    if (failed == 0) {
        ; //fprintf(stderr, "[+] atom.base64b: all %d tests passed!\n", num_tests);
    } else {
        fprintf(stderr, "[-] atom.base64b: %d out of %d tests failed\n", failed, num_tests);
        return 1;
    }
    
    return 0;
}
