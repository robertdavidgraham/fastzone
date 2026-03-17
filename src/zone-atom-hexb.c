
#include "zone-atom.h"
#include "zone-parse.h"
#include "zone-parse-record.h"
#include "zone-error.h"
#include "zone-parse-token.h"
#include "util-hex16.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>



/* -------------------------------------------------------------------------- */
/* zone_atom_hex_l(): length-prefixed                                         */
/* -------------------------------------------------------------------------- */

size_t
zone_atom_hexl_b(const char *data, size_t cursor, size_t max,
                struct wire_record_t *out) {
    /*
     * Find the length of the HEX16 substring using fast SIMD.
     */
    parsetokens_t tokens = {0};
    size_t length = parse_token_length(data, cursor, &tokens);
    if (length == 0 || length >= 256)
        return PARSE_ERR(1, cursor, max, out);
    
    /*
     * Prepend this length
     */
    wire_append_uint8(out, (uint8_t)length);
    
    /*
     * Now decode the hex
     */
    size_t outlen = 0;
    int is_good = base16_decode(data + cursor, length, out->wire.buf, &outlen);
    if (!is_good || outlen == 0)
        return PARSE_ERR(1, cursor, max, out);

    out->wire.len += outlen;
    cursor += outlen;
    return cursor;
}

/* -------------------------------------------------------------------------- */
/* zone_atom_hex_c(): continuous, no length prefix                             */
/* -------------------------------------------------------------------------- */

size_t
zone_atom_hexc_b(const char *data, size_t cursor, size_t max,
                struct wire_record_t *out)
{
    /*
     * Find the length of the HEX16 substring using fast SIMD.
     */
    parsetokens_t tokens = {0};
    size_t length = parse_token_length(data, cursor, &tokens);
    if (length == 0 || length >= 256)
        return PARSE_ERR(1, cursor, max, out);
    

    /*
     * Now decode the hex
     */
    size_t outlen = 0;
    int is_good = base16_decode(data + cursor, length, out->wire.buf, &outlen);
    if (!is_good || outlen == 0)
        return PARSE_ERR(1, cursor, max, out);

    out->wire.len += outlen;
    cursor += length;
    return cursor;
}



/* -------------------------------------------------------------------------- */
/* zone_atom_hexes(): not continuous, separated by space                      */
/* -------------------------------------------------------------------------- */

size_t
zone_atom_hexes_b(const char *data, size_t cursor, size_t max,
                struct wire_record_t *out, unsigned *depth)
{
    for (;;) {
        /*
         * Find the length of the HEX16 substring using fast SIMD.
         */
        parsetokens_t tokens = {0};
        size_t length = parse_token_length(data, cursor, &tokens);
        if (length == 0 || length >= 256)
            return PARSE_ERR(1, cursor, max, out);
        
        
        /*
         * Now decode the hex
         */
        size_t outlen = 0;
        int is_good = base16_decode(data + cursor,
                                    length & (~1), /* only an even number of input chars */
                                    out->wire.buf + out->wire.len,
                                    &outlen);
        if (!is_good || outlen == 0)
            return zone_atom_hexes_a(data, cursor, max, out, depth);

        out->wire.len += outlen;
        cursor += length & (~1);

        /*
         * If we have an odd number of hex digits, go to the slower path
         */
        if (length & 1)
            return zone_atom_hexes_a(data, cursor, max, out, depth);

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
    return cursor;
}


size_t
zone_atom_hexels_b(const char *data, size_t cursor, size_t max,
                struct wire_record_t *out, unsigned *depth) {
   
    /*
     * add a byte that will be our length field.
     */
    size_t len_offset = out->wire.len;
    wire_append_uint8(out, 0);
    
    /*
     * Do the parsing
     */
    size_t next = zone_atom_hexes_b(data, cursor, max, out, depth);
    
    /*
     * Write the length byte
     */
    size_t length = out->wire.len - len_offset - 1;
    if (length >= 256)
        return PARSE_ERR(1, cursor, max, out);
    out->wire.buf[len_offset] = (unsigned char)length;
    
    return next;
}

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

struct tc_hexes {
    const char *input;
    size_t expected_hex_bytes;
    const uint8_t expected[16];
};

static const struct tc_hexes tests[] = {

    { "A BCD\n", 2, { 0xAB, 0xCD } },

    { "AB\n", 1, { 0xAB } },

    { "ABCD\n", 2, { 0xAB, 0xCD } },

    { "AB  CD\r\n", 2, { 0xAB, 0xCD } },

    { "AB CD EF\n", 3, { 0xAB, 0xCD, 0xEF } },

    { "A BCD\n", 2, { 0xAB, 0xCD } },

    { "A1 2 34 5\n", 3, { 0xA1, 0x23, 0x45 } },

    { "12  34   56 78\n", 4, { 0x12, 0x34, 0x56, 0x78 } },

    { "A B C D  \n", 2, { 0xAB, 0xCD } },

    { "00112233445566778899AABBCCDDEEFF\n", 16, { 0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF } },
    {0}
};

int zone_atom_hexb_selftest(void) {
    size_t i;

    for (i = 0; tests[i].input; i++) {
        struct wire_record_t out_hexes;
        struct wire_record_t out_hexels;
        unsigned depth_hexes = 0;
        unsigned depth_hexels = 0;
        size_t cursor_hexes;
        size_t cursor_hexels;
        size_t hexes_len;
        size_t hexels_len;
        unsigned char bufes[1024];
        unsigned char bufels[1024];

        memset(&out_hexes, 0, sizeof(out_hexes));
        memset(&out_hexels, 0, sizeof(out_hexels));
        
        out_hexes.wire.buf = bufes;
        out_hexes.wire.max = 100;
        out_hexels.wire.buf = bufels;
        out_hexels.wire.max = 100;
        

        cursor_hexes = zone_atom_hexes_b(
            tests[i].input,
            0,
            strlen(tests[i].input),
            &out_hexes,
            &depth_hexes
        );

        cursor_hexels = zone_atom_hexels_b(
            tests[i].input,
            0,
            strlen(tests[i].input),
            &out_hexels,
            &depth_hexels
        );

        if (cursor_hexes != cursor_hexels) {
            fprintf(stderr,
                "hexes[%zu] parse failure: hexes=%lld hexels=%lld input=\"%s\"\n",
                i, (long long)cursor_hexes, (long long)cursor_hexels, tests[i].input);
            return 1;
        }

        hexes_len  = out_hexes.wire.len;
        hexels_len = out_hexels.wire.len;

        /*
         * 1. Verify both decoders produced the same payload.
         *    hexels has a one-byte length prefix, so compare:
         *      hexes.buf[0 .. hexes_len-1]
         *      hexels.buf[1 .. hexels_len-1]
         */
        if (hexels_len != hexes_len + 1) {
            fprintf(stderr,
                "test[%zu] length mismatch between hexes/hexels: "
                "hexes=%zu hexels=%zu input=\"%s\"\n",
                i, hexes_len, hexels_len, tests[i].input);
            return 1;
        }

        if (out_hexels.wire.buf[0] != hexes_len) {
            fprintf(stderr,
                "test[%zu] bad hexels length prefix: got=%u expected=%zu input=\"%s\"\n",
                i,
                (unsigned)out_hexels.wire.buf[0],
                hexes_len,
                tests[i].input);
            return 1;
        }

        if (memcmp(out_hexes.wire.buf,
                   out_hexels.wire.buf + 1,
                   hexes_len) != 0) {
            size_t j;
            fprintf(stderr,
                "test[%zu] decoded payload mismatch between hexes and hexels input=\"%s\"\n",
                i, tests[i].input);

            fprintf(stderr, "  hexes :");
            for (j = 0; j < hexes_len; j++)
                fprintf(stderr, " %02x", out_hexes.wire.buf[j]);
            fprintf(stderr, "\n");

            fprintf(stderr, "  hexels:");
            for (j = 0; j < hexels_len; j++)
                fprintf(stderr, " %02x", out_hexels.wire.buf[j]);
            fprintf(stderr, "\n");

            return 1;
        }

        /*
         * 2. Verify expected decoded length.
         */
        if (hexes_len != tests[i].expected_hex_bytes) {
            fprintf(stderr,
                "test[%zu] wrong decoded length: got=%zu expected=%zu input=\"%s\"\n",
                i, hexes_len, tests[i].expected_hex_bytes, tests[i].input);
            return 1;
        }

        /*
         * hexels length is already indirectly checked above:
         *   hexels_len == hexes_len + 1
         *   hexels.buf[0] == hexes_len
         */

        /*
         * 3. Verify decoded payload against expected bytes.
         *    Only need to check hexes(), since hexels() was already
         *    proven to match hexes() apart from the prefix.
         */
        if (memcmp(out_hexes.wire.buf,
                   tests[i].expected,
                   tests[i].expected_hex_bytes) != 0) {
            size_t j;
            fprintf(stderr,
                "test[%zu] decoded payload does not match expected input=\"%s\"\n",
                i, tests[i].input);

            fprintf(stderr, "  got     :");
            for (j = 0; j < hexes_len; j++)
                fprintf(stderr, " %02x", out_hexes.wire.buf[j]);
            fprintf(stderr, "\n");

            fprintf(stderr, "  expected:");
            for (j = 0; j < tests[i].expected_hex_bytes; j++)
                fprintf(stderr, " %02x", tests[i].expected[j]);
            fprintf(stderr, "\n");

            return 1;
        }
    }

    return 0;
}
