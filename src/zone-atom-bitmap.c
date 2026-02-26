/* zone-atom-bitmap.c
 *
 * Implements:
 *   - zone_atom_type()   : parse a DNS RR TYPE token (e.g. "A", "MX", "TYPE65280")
 *                          and append the 16-bit type code to wire.
 *   - zone_atom_bitmap() : parse an RFC-style RR type bitmap list (NSEC/NSEC3):
 *                          e.g. "A NS SOA MX RRSIG NSEC DNSKEY"
 *                          and append the type bitmaps to wire.
 *
 * Also includes:
 *   - zone_atom_bitmap_quicktest() : small tests (including multiline/parens).
 *
 * Design priorities:
 *   - Simple and well-documented.
 *   - Avoid per-character error branching where reasonable; accumulate errors
 *     and report once.
 *
 * Dependencies (declared elsewhere):
 *   - size_t zone_parse_space(const char *data, size_t cursor, size_t max,
 *                             struct wire_record_t *out, unsigned *depth);
 *   - void wire_append_uint16(struct wire_record_t *out, uint16_t v, int *err);
 *   - void wire_append_uint8(struct wire_record_t *out, uint8_t v, int *err);
 *   - void wire_append_bytes(struct wire_record_t *out, const void *p, size_t n, int *err);
 *   - unsigned zone_atom_type_lookup(const char *data, size_t length, unsigned *type_value);
 *
 * Notes:
 *   - zone_parse_space() is used to skip separators, comments, and parentheses.
 *   - This code expects zone_parse_space() to update *depth for '(' and ')'.
 */

#include "zone-parse.h"
#include "zone-atom.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* -------------------------------------------------------------------------- */
/* small helpers                                                              */
/* -------------------------------------------------------------------------- */

static int
is_digit(char c)
{
    return c >= '0' && c <= '9';
}

/*static int
is_alpha(char c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}*/



/* Parse "TYPE12345" into numeric value; returns 1 on success */
static int
parse_TYPE_decimal(const char *data, size_t len, unsigned *out_type)
{
    if (len < 5)
        return 0;
    if (!(data[0] == 'T' || data[0] == 't')) return 0;
    if (!(data[1] == 'Y' || data[1] == 'y')) return 0;
    if (!(data[2] == 'P' || data[2] == 'p')) return 0;
    if (!(data[3] == 'E' || data[3] == 'e')) return 0;

    unsigned v = 0;
    for (size_t i = 4; i < len; i++) {
        char c = data[i];
        if (!is_digit(c))
            return 0;
        v = v * 10u + (unsigned)(c - '0');
        if (v > 65535u)
            return 0;
    }

    *out_type = v;
    return 1;
}

/* -------------------------------------------------------------------------- */
/* zone_atom_type                                                             */
/* -------------------------------------------------------------------------- */

#include <stdint.h>
#include <stddef.h>

/* you already have: unsigned ctz64(uint64_t x); */

static inline unsigned
first_set_byte64(uint64_t x)
{
    /* x has 0x80 in matching bytes */
    return (unsigned)(ctz64(x) >> 3);
}

static size_t
token_length(const char *data, size_t cursor, size_t max)
{
    (void)max; /* unused in this simple version */

    const uint64_t *p = (const uint64_t *)(const void *)(data + cursor);
    uint64_t v0 = p[0];
    uint64_t v1 = p[1];

    const uint64_t ones = 0x0101010101010101ULL;
    const uint64_t high = 0x8080808080808080ULL;

    const uint64_t sp  = 0x2020202020202020ULL; /* ' ' */
    const uint64_t tab = 0x0909090909090909ULL; /* '\t' */

    /* chunk 0: detect (byte == ' ') OR (byte == '\t') */
    uint64_t x0s = v0 ^ sp;
    uint64_t m0s = (x0s - ones) & ~x0s & high;

    uint64_t x0t = v0 ^ tab;
    uint64_t m0t = (x0t - ones) & ~x0t & high;

    uint64_t m0 = m0s | m0t;
    if (m0)
        return first_set_byte64(m0);

    /* chunk 1 */
    uint64_t x1s = v1 ^ sp;
    uint64_t m1s = (x1s - ones) & ~x1s & high;

    uint64_t x1t = v1 ^ tab;
    uint64_t m1t = (x1t - ones) & ~x1t & high;

    uint64_t m1 = m1s | m1t;
    if (m1)
        return 8u + first_set_byte64(m1);

    return 16;
}
/*
 * Parse a TYPE token and append uint16 type code to wire.
 *
 * Typical values:
 *   A, AAAA, NS, MX, SOA, TXT, RRSIG, DNSKEY, ...
 *   TYPE65280
 *
 * Uses zone_atom_type_lookup(name,len,&typeval).
 * If not found:
 *   - If it matches TYPEdddd, we accept that numeric type.
 *   - Otherwise mark an error.
 */
size_t
zone_atom_type(const char *data, size_t cursor, size_t max,
               struct wire_record_t *out)
{
    unsigned type_value = 0;
    size_t length = token_length(data, cursor, max);

    if (length < 16) {
        unsigned found = zone_type2_lookup(data + cursor, length, &type_value);
        if (found) {
            wire_append_uint16(out, (uint16_t)type_value);
            return cursor + length;
        }
    }
    

    /* measure token length: stop at space-equivalent markers.
     * We rely on zone_parse_space() to skip those; here we just
     * scan until we hit something that is a likely delimiter.
     *
     * To keep this atom independent of your exact delimiter set,
     * we stop on space/tab and on obvious record structure chars.
     */
    size_t start = cursor;
    while (cursor < max) {
        char c = data[cursor];
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == ';' || c == '(' || c == ')')
            break;
        cursor++;
    }
    size_t len = cursor - start;

    if (len == 0) {
        return PARSE_ERR(1, cursor, max, out);
    }

    unsigned found = zone_type2_lookup(data + start, len, &type_value);

    if (!found) {
        /* try TYPEdddd */
        if (!parse_TYPE_decimal(data + start, len, &type_value)) {
            PARSE_ERR(1, cursor, max, out);
            type_value = 0;
        }
    }

    wire_append_uint16(out, (uint16_t)type_value);

    return cursor;
}

/* -------------------------------------------------------------------------- */
/* zone_atom_bitmap                                                           */
/* -------------------------------------------------------------------------- */

/*
 * Parse a sequence of type names and build RFC type bitmaps as used in NSEC/NSEC3.
 *
 * Input (presentation):
 *   A NS SOA MX RRSIG NSEC DNSKEY
 * possibly spread across whitespace and parentheses.
 *
 * Output (wire):
 *   One or more windows:
 *     window_block (1 byte)
 *     bitmap_len   (1 byte)  (1..32)
 *     bitmap_bytes (bitmap_len bytes)
 *
 * Types are set as bits:
 *   window = type / 256
 *   bitpos = type % 256
 *   octet  = bitpos / 8
 *   mask   = 1 << (7 - (bitpos % 8))
 *
 * Practical approach (simple, not super optimized):
 *   - Collect types into a boolean table [0..65535] is too large.
 *   - Instead, collect them into an array (up to some max), then build per-window bitmaps.
 * For simplicity, we do:
 *   - a small fixed array of up to 256 type values; beyond that we flag error.
 *   - then we build bitmaps by scanning that array and setting bits in a 32-byte window bitmap.
 *
 * Error accumulation:
 *   - If any token is unknown and not TYPEdddd, we set err once (but keep going).
 */
size_t
zone_atom_bitmap(const char *data, size_t cursor, size_t max,
                 struct wire_record_t *out, unsigned *depth)
{
    if (cursor > max)
        return max + 1;

    unsigned types[256];
    size_t type_count = 0;

    /* Parse tokens until end-of-record-ish marker.
     * We use zone_parse_space() to advance between tokens, including multiline.
     */
    while (cursor < max) {
        /* stop at record terminators */
        char c = data[cursor];
        if (c == '\r' || c == '\n')
            break;
    
        /* measure token */
        size_t start = cursor;
        while (cursor < max) {
            char c = data[cursor];
            if (c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == ';' || c == '(' || c == ')')
                break;
            cursor++;
        }
        size_t len = cursor - start;
        if (len == 0)
            break;

        unsigned type_value = 0;
        unsigned found = zone_type2_lookup(data + start, len, &type_value);

        if (!found) {
            if (!parse_TYPE_decimal(data + start, len, &type_value)) {
                PARSE_ERR(1, cursor, max, out);

                /* skip unknown token */
                continue;
            }
        }

        if (type_count < sizeof(types)/sizeof(types[0])) {
            types[type_count++] = type_value;
        } else {
            PARSE_ERR(1, cursor, max, out);
        }
        
        cursor = zone_parse_space(data, cursor, max, out, depth);
    }
    

    /* Build bitmaps:
     * We will output windows in ascending order. For each window 0..255 that
     * appears, we create up to 32 bytes (256 bits). Then trim trailing zeros.
     */
    uint8_t present_window[256];
    memset(present_window, 0, sizeof(present_window));
    for (size_t i = 0; i < type_count; i++) {
        unsigned w = (types[i] >> 8) & 0xFFu;
        present_window[w] = 1;
    }

    for (unsigned w = 0; w < 256; w++) {
        if (!present_window[w])
            continue;

        uint8_t bm[32];
        memset(bm, 0, sizeof(bm));

        for (size_t i = 0; i < type_count; i++) {
            unsigned t = types[i];
            if (((t >> 8) & 0xFFu) != w)
                continue;

            unsigned bit = t & 0xFFu;
            unsigned octet = bit >> 3;
            unsigned sh = bit & 7u;
            bm[octet] |= (uint8_t)(1u << (7u - sh));
        }

        /* Trim trailing zero octets */
        unsigned bm_len = 32;
        while (bm_len > 0 && bm[bm_len - 1] == 0)
            bm_len--;

        if (bm_len == 0) {
            /* shouldn't happen if window marked present, but be safe */
            continue;
        }

        wire_append_uint8(out, (uint8_t)w);
        wire_append_uint8(out, (uint8_t)bm_len);
        wire_append_bytes(out, bm, bm_len);
    }

    return cursor;
}

/* -------------------------------------------------------------------------- */
/* Quicktest                                                                  */
/* -------------------------------------------------------------------------- */

static int
bytes_eq(const uint8_t *a, const uint8_t *b, size_t n)
{
    return memcmp(a, b, n) == 0;
}

int
zone_atom_bitmap_quicktest(void)
{
    int failures = 0;

    struct {
        const char *in;
        const uint8_t *exp;
        size_t exp_len;
        const char *what;
    } tcs[] = {
        /* 1) Single type */
        {
            "A\n",
            (const uint8_t[]){ 0x00,0x01,0x40 }, /* window 0, len 1, bit for A(1) => 0x40 */
            3,
            "bitmap: A"
        },

        /* 2) Two types in same window */
        {
            "A NS\n",
            (const uint8_t[]){ 0x00,0x01,0x60 }, /* A(1)=0x40, NS(2)=0x20 */
            3,
            "bitmap: A NS"
        },

        /* 3) Type in higher window (TYPE256) and A */
        {
            "A TYPE256\n",
            (const uint8_t[]){
                0x00,0x01,0x40,      /* window 0: A */
                0x01,0x01,0x80       /* window 1: type 256 => bit 0 => 0x80 */
            },
            6,
            "bitmap: A TYPE256"
        },

        /* 4) Multiline parentheses with varying locations */
        {
            "( A\n  NS )\n",
            (const uint8_t[]){ 0x00,0x01,0x60 },
            3,
            "bitmap: (A NS) multiline"
        },

        /* 5) More realistic list with comment inside parens */
        {
            "(\n  A  NS  ; comment here\n  RRSIG\n)\n",
            /* RRSIG is type 46 => window 0, need len 6, byte0 0x60, byte5 bit(46)->0x02 */
            (const uint8_t[]){ 0x00,0x06, 0x60,0x00,0x00,0x00,0x00,0x02 },
            8,
            "bitmap: A NS RRSIG with comment"
        },
    };

    for (size_t i = 0; i < sizeof(tcs)/sizeof(tcs[0]); i++) {
        uint8_t wire[128 + 1024];
        struct wire_record_t out = {0};
        unsigned depth = 0;
        out.wire.buf = wire;
        out.wire.max = 128;
        size_t max = strlen(tcs[i].in);
        
        /*
         * Call test function
         */
        zone_atom_bitmap(tcs[i].in, 0, max, &out, &depth);

        if (out.err.code != 0) {
            fprintf(stderr, "bitmap tc[%zu] %s: err_code=%u cursor=%zu\n",
                    i, tcs[i].what, out.err.code, out.err.cursor);
            failures++;
            continue;
        }

        if (out.wire.len != tcs[i].exp_len || !bytes_eq(out.wire.buf, tcs[i].exp, tcs[i].exp_len)) {
            fprintf(stderr, "bitmap tc[%zu] %s: mismatch\n", i, tcs[i].what);
            fprintf(stderr, "  got (%zu): ", out.wire.len);
            for (size_t k = 0; k < out.wire.len; k++)
                fprintf(stderr, "%02x", out.wire.buf[k]);
            fprintf(stderr, "\n  exp (%zu): ", tcs[i].exp_len);
            for (size_t k = 0; k < tcs[i].exp_len; k++)
                fprintf(stderr, "%02x", tcs[i].exp[k]);
            fprintf(stderr, "\n");
            failures++;
            continue;
        }
    }

    /* quick tests for zone_atom_type() */
    {
        struct {
            const char *in;
            uint16_t exp_type;
            const char *what;
        } ttype[] = {
            { "A\n", 1, "type A" },
            { "TYPE255\n", 255, "type TYPE255" },
        };

        for (size_t i = 0; i < sizeof(ttype)/sizeof(ttype[0]); i++) {
            uint8_t wire[16+1024];
            struct wire_record_t out = {0};
            out.wire.buf = wire;
            out.wire.len = 0;
            out.wire.max = 16;

            (void)zone_atom_type(ttype[i].in, 0, strlen(ttype[i].in), &out);

            if (out.err.code != 0) {
                fprintf(stderr, "type tc[%zu] %s: err_code=%u cursor=%zu\n",
                        i, ttype[i].what, out.err.code, out.err.cursor);
                failures++;
                continue;
            }

            if (out.wire.len != 2) {
                fprintf(stderr, "type tc[%zu] %s: bad wire len=%zu\n",
                        i, ttype[i].what, out.wire.len);
                failures++;
                continue;
            }

            uint16_t got = (uint16_t)((wire[0] << 8) | wire[1]);
            if (got != ttype[i].exp_type) {
                fprintf(stderr, "type tc[%zu] %s: got=%u exp=%u\n",
                        i, ttype[i].what, (unsigned)got, (unsigned)ttype[i].exp_type);
                failures++;
                continue;
            }
        }
    }

    if (failures == 0)
        printf("zone_atom_bitmap_quicktest: OK\n");
    else
        printf("zone_atom_bitmap_quicktest: FAIL (%d)\n", failures);

    return failures;
}

