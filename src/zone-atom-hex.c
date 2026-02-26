
#include "zone-atom.h"
#include "zone-parse.h"
#include "zone-parse-record.h"
#include "zone-error.h"

static int is_space_equiv(char c)
{
    return c == ' '  || c == '\t' ||
           c == '\r' || c == '\n' ||
           c == ';'  || c == '('  || c == ')';
}

/*
 * HEX atoms (base16) in your zone_atom_int16() style:
 *
 *  - zone_atom_hex():   parses a single continuous hex token with NO whitespace inside
 *  - zone_atom_hexes(): parses hex across the remainder of a record, allowing spaces/tabs
 *                       and using zone_parse_space() (so it respects comments/paren depth)
 *
 * Special case:
 *  - A single '-' token means “empty field” (append zero bytes) and consumes that '-'
 *
 * Error style:
 *  - If cursor > max: return max+1
 *  - On parse problems, set out->err_code=1 and out->err_cursor=cursor (only once)
 *
 * Assumed helpers exist:
 *   size_t zone_parse_space(const char *data, size_t cursor, size_t max,
 *                           struct wire_record_t *out, unsigned *depth);
 *   void wire_append_uint8(struct wire_record_t *out, uint8_t v, int *err);
 */

#include <stddef.h>
#include <stdint.h>

static int
is_digit(char c)
{
    return c >= '0' && c <= '9';
}

static int
is_hex_alpha(char c)
{
    return (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

static int
is_hex_digit(char c)
{
    return is_digit(c) || is_hex_alpha(c);
}

static unsigned
hex_value(char c)
{
    if (c >= '0' && c <= '9')
        return (unsigned)(c - '0');
    if (c >= 'a' && c <= 'f')
        return 10u + (unsigned)(c - 'a');
    return 10u + (unsigned)(c - 'A');
}


/* zone-atom-hex.c
 *
 * Two hex atoms:
 *   - zone_atom_hex_l(): decodes a continuous hex token, prefixes with 1-byte length,
 *                        then appends decoded bytes.
 *   - zone_atom_hex_c(): decodes a continuous hex token, appends decoded bytes only
 *                        (no length prefix).
 *
 * Shared rules (per your latest requirements):
 *   - Decode via 256-byte lookup table:
 *       * valid hex => 0..15
 *       * invalid   => high bit set (0x80)
 *   - Continue consuming while characters are hex (table entry < 0x80).
 *     Stop at the first non-hex character.
 *   - At end:
 *       * error if odd number of digits
 *       * error if terminator is NOT is_space_equiv()
 *   - Special case: '-' means empty field (and must still be terminated by
 *     is_space_equiv()).
 *
 * Caller contract:
 *   - Caller positions cursor at token start (whitespace already handled).
 *   - This atom does NOT skip whitespace; it enforces token termination.
 *
 * Error handling:
 *   - If cursor > max: return max+1
 *   - On error, set out->err_code=1 and out->err_cursor once.
 *   - Best-effort forward progress: even on errors, we still append what we
 *     decoded so far (and in _l() we still append the length byte).
 */

#include "zone-parse.h"
#include "zone-atom.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>




/* 0..15 => valid nibble, 0x80 => invalid */
static const uint8_t hexdec[256] = {
#define XX 0x80
    /* 0x00..0x0F */
    XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,
    /* 0x10..0x1F */
    XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,
    /* 0x20..0x2F */
    XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,
    /* 0x30..0x3F */
     0, 1, 2, 3, 4, 5, 6, 7, 8, 9, XX,XX,XX,XX,XX,XX,
    /* 0x40..0x4F */
    XX,10,11,12,13,14,15,XX,XX,XX,XX,XX,XX,XX,XX,XX,
    /* 0x50..0x5F */
    XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,
    /* 0x60..0x6F */
    XX,10,11,12,13,14,15,XX,XX,XX,XX,XX,XX,XX,XX,XX,
    /* 0x70..0x7F */
    XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,

    /* 0x80..0xFF invalid */
    XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,
    XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,
    XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,
    XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,
    XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,
    XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,
    XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,
    XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX
#undef XX
};

struct hex_decode_result {
    size_t cursor_end;      /* cursor positioned at first non-hex char */
    size_t decoded_len;
    uint8_t decoded[255];   /* enough for length-prefixed form */
    uint8_t err_flag;       /* 0x80 if any error */
    size_t err_cursor;      /* first error position */
    int saw_any;            /* consumed at least one digit, or '-' */
};

/* Shared decode core.
 * If allow_dash is true, '-' yields empty.
 * Terminator must be is_space_equiv() (otherwise error).
 */
static struct hex_decode_result
hex_decode_core(const char *data, size_t cursor, size_t max)
{
    struct hex_decode_result r;
    memset(&r, 0, sizeof(r));
    r.cursor_end = cursor;
    r.decoded_len = 0;
    r.err_flag = 0;
    r.err_cursor = (size_t)(~(size_t)0);
    r.saw_any = 0;

    if (cursor > max) {
        r.cursor_end = max + 1;
        r.err_flag = 0x80;
        r.err_cursor = cursor;
        return r;
    }

    size_t start = cursor;

    /* '-' => empty */
    if (cursor < max && data[cursor] == '-') {
        r.saw_any = 1;
        cursor++;
        r.cursor_end = cursor;

        if (cursor >= max || !is_space_equiv(data[cursor])) {
            r.err_flag |= 0x80;
            r.err_cursor = start;
        }
        return r;
    }

    uint8_t have_hi = 0;
    uint8_t hi = 0;

    while (cursor < max) {
        unsigned char ch = (unsigned char)data[cursor];
        uint8_t v = hexdec[ch];
        if (v & 0x80)
            break;

        r.saw_any = 1;

        if (!have_hi) {
            hi = v;
            have_hi = 1;
        } else {
            uint8_t byte = (uint8_t)((hi << 4) | v);
            have_hi = 0;

            if (r.decoded_len < sizeof(r.decoded)) {
                r.decoded[r.decoded_len++] = byte;
            } else {
                if (r.err_cursor == (size_t)(~(size_t)0))
                    r.err_cursor = cursor;
                r.err_flag |= 0x80;
            }
        }

        cursor++;
    }

    r.cursor_end = cursor;

    /* No digits at all is an error */
    if (!r.saw_any) {
        r.err_flag |= 0x80;
        r.err_cursor = start;
    }

    /* Odd digit count is an error */
    if (have_hi) {
        r.err_flag |= 0x80;
        if (r.err_cursor == (size_t)(~(size_t)0))
            r.err_cursor = cursor;
    }

    /* Must terminate with space-equivalent */
    if (cursor >= max || !is_space_equiv(data[cursor])) {
        r.err_flag |= 0x80;
        if (r.err_cursor == (size_t)(~(size_t)0))
            r.err_cursor = cursor;
    }

    return r;
}

/* -------------------------------------------------------------------------- */
/* zone_atom_hex_l(): length-prefixed                                         */
/* -------------------------------------------------------------------------- */

size_t
zone_atom_hex_l(const char *data, size_t cursor, size_t max,
                struct wire_record_t *out)
{
    struct hex_decode_result r = hex_decode_core(data, cursor, max);
    
    /* Emit: length + bytes (best-effort even on error) */
    
    wire_append_uint8(out, (uint8_t)r.decoded_len);
    if (r.decoded_len)
        wire_append_bytes(out, r.decoded, r.decoded_len);


    if (r.err_flag & 0x80) {
        if (r.err_cursor == (size_t)(~(size_t)0))
            r.err_cursor = cursor;
        PARSE_ERR(1, r.err_cursor, max, out);
    }

    return r.cursor_end;
}

/* -------------------------------------------------------------------------- */
/* zone_atom_hex_c(): continuous, no length prefix                             */
/* -------------------------------------------------------------------------- */

size_t
zone_atom_hex_c(const char *data, size_t cursor, size_t max,
                struct wire_record_t *out)
{
    struct hex_decode_result r = hex_decode_core(data, cursor, max);
    
    /* Emit: bytes only */
    if (r.decoded_len)
        wire_append_bytes(out, r.decoded, r.decoded_len);


    if (r.err_flag & 0x80) {
        if (r.err_cursor == (size_t)(~(size_t)0))
            r.err_cursor = cursor;
        PARSE_ERR(1, r.err_cursor, max, out);
    }

    return r.cursor_end;
}



size_t
zone_atom_hexes(const char *data, size_t cursor, size_t max,
                struct wire_record_t *out, unsigned *depth)
{
    if (cursor >= max)
        return cursor;


    /* "-" means empty field */
    if (data[cursor] == '-') {
        cursor++;
        /* and then move forward, per your convention */
        cursor = zone_parse_space(data, cursor, max, out, depth);
        return cursor;
    }

    unsigned have_nibble = 0;
    unsigned hi = 0;
    unsigned saw_any_hex = 0;

    for (;;) {
        if (cursor > max)
            return max + 1;
        if (cursor == max)
            break;

        /* Respect zonefile whitespace/comments/paren depth */
        if (data[cursor] == ' ' || data[cursor] == '\t') {
            cursor = zone_parse_space(data, cursor, max, out, depth);
            if (cursor > max)
                return max + 1;
            if (cursor == max)
                break;
        }

        char c = data[cursor];

        /* Stop at end-of-record markers; leave them to outer finish/space logic */
        if (c == ';' || c == '\r' || c == '\n')
            break;

        if (!is_hex_digit(c)) {
            /* Non-hex character inside hexes field */
            PARSE_ERR(1, cursor, max, out);
            break;
        }

        saw_any_hex = 1;

        unsigned v = hex_value(c);
        if (!have_nibble) {
            hi = v;
            have_nibble = 1;
        } else {
            unsigned byte = (hi << 4) | v;
            wire_append_uint8(out, (uint8_t)byte);
            have_nibble = 0;
        }

        cursor++;
    }

    if (!saw_any_hex) {
        PARSE_ERR(1, cursor, max, out);
    } else if (have_nibble) {
        PARSE_ERR(1, cursor, max, out);
    }

    /* keep moving forward after the blob */
    cursor = zone_parse_space(data, cursor, max, out, depth);
    return cursor;
}

size_t
zone_atom_hexes_c(const char *data, size_t cursor, size_t max,
                struct wire_record_t *out, unsigned *depth) {
   
    /*
     * add a byte that will be our length field.
     */
    size_t len_offset = out->wire.len;
    wire_append_uint8(out, 0);
    
    /*
     * Do the parsinging
     */
    size_t next = zone_atom_hexes(data, cursor, max, out, depth);
    
    /*
     * Write the length byte
     */
    size_t length = out->wire.len - len_offset - 1;
    if (length >= 256)
        return PARSE_ERR(1, cursor, max, out);
    out->wire.buf[len_offset] = length;
    
    return next;
}

