

#include "zone-atom.h"
#include "zone-parse.h"
#include "zone-parse-record.h"
#include "zone-error.h"

/* zone-atom-caaval.c
 *
 * CAA “value” atom parser (RFC 8659 presentation format)
 *
 * Context:
 *   CAA wire format is:
 *     Flags (1 octet)
 *     TagLen (1 octet)
 *     Tag (TagLen octets)
 *     Value (remaining octets)
 *
 * In zonefile (presentation) format, the value is written like a “character-string”
 * in the sense that:
 *   - If it contains spaces, it must be quoted:  "letsencrypt.org"
 *   - Backslash escapes are allowed, including \DDD decimal escapes (0..255)
 *
 * IMPORTANT DIFFERENCE vs TXT/SPF atoms:
 *   - TXT on-the-wire is <len byte><bytes> for each chunk.
 *   - CAA Value in wire format has NO length byte. It is raw bytes until RDLEN.
 *   - Therefore this atom appends ONLY the raw bytes, with no leading length.
 *
 * Parsing rules implemented:
 *   - Leading space-equivalents are tolerated by skipping via zone_parse_space()
 *     at the *call site* (recommended), but this function also tolerates plain
 *     ' ' and '\t' skips just in case.
 *   - Quoted value:
 *       " ... " supports:
 *         \\  \"  and \DDD (three decimal digits)
 *       Any byte except terminating quote is permitted inside.
 *   - Unquoted value:
 *       Reads a single token until a “space-equivalent” delimiter:
 *         space, tab, CR, LF, ';', '(', ')'
 *       Supports the same backslash escapes.
 *   - If the next token is exactly "-" (dash), treat as empty value (consume '-' only).
 *   - If cursor > max: return max+1
 *   - On errors: set out->err_code=1 and out->err_cursor once (same style as your int16)
 *
 * Assumed external helpers/struct:
 *   - struct wire_record_t { ... err_code, err_cursor ... }
 *   - void wire_append_uint8(struct wire_record_t *out, uint8_t v, int *err);
 *   - void wire_append_bytes(struct wire_record_t *out, const void *p, size_t n, int *err);
 */

#include <stddef.h>
#include <stdint.h>

/* You likely have your own header; include it if appropriate. */
/* #include "zone-atom.h" */

static int
is_digit(char c)
{
    return c >= '0' && c <= '9';
}

/* “Space equivalent” delimiters for your grammar */
static int
is_space_equiv(char c)
{
    return c == ' '  || c == '\t' ||
           c == '\r' || c == '\n' ||
           c == ';'  || c == '('  || c == ')';
}


/* Parse \DDD (exactly three decimal digits) -> byte 0..255 */
static int
parse_ddd_byte(const char *data, size_t cursor, size_t max, uint8_t *out_byte)
{
    if (cursor + 2 >= max)
        return 0;

    char a = data[cursor + 0];
    char b = data[cursor + 1];
    char c = data[cursor + 2];

    if (!is_digit(a) || !is_digit(b) || !is_digit(c))
        return 0;

    unsigned v = (unsigned)(a - '0') * 100u
               + (unsigned)(b - '0') * 10u
               + (unsigned)(c - '0');

    if (v > 255u)
        return 0;

    *out_byte = (uint8_t)v;
    return 1;
}

/*
 * zone_atom_caaval()
 *
 * Typical values:
 *   "letsencrypt.org"
 *   "mailto:hostmaster@example.com"
 *   iodef="https://example.com/caa-report"
 *   -
 *
 * NOTE: This appends RAW bytes only (no length prefix).
 */
size_t
zone_atom_caaval(const char *data, size_t cursor, size_t max,
                 struct wire_record_t *out)
{
    /* match your int16 style */
    if (cursor > max)
        return max + 1;

    /* tolerant: skip plain spaces/tabs (caller often already did zone_parse_space) */
    while (cursor < max && (data[cursor] == ' ' || data[cursor] == '\t'))
        cursor++;

    if (cursor > max)
        return max + 1;

    if (cursor == max) {
        return PARSE_ERR(1, cursor, max, out);
    }

    /* "-" means empty value */
    if (data[cursor] == '-') {
        cursor++;
        return cursor;
    }

    /* We'll stream bytes directly to wire */
    

    if (data[cursor] == '"') {
        /* quoted */
        cursor++; /* consume opening quote */

        for (;;) {
            if (cursor > max)
                return max + 1;
            if (cursor == max) {
                /* unterminated quote */
                PARSE_ERR(1, cursor, max, out);
                break;
            }

            char c = data[cursor];

            if (c == '"') {
                cursor++; /* consume closing quote */
                break;
            }

            if (c == '\\') {
                cursor++;
                if (cursor > max)
                    return max + 1;
                if (cursor == max) {
                    PARSE_ERR(1, cursor, max, out);
                    break;
                }

                char e = data[cursor];

                if (is_digit(e)) {
                    uint8_t v;
                    if (!parse_ddd_byte(data, cursor, max, &v)) {
                        PARSE_ERR(1, cursor, max, out);
                        cursor++; /* consume something to make progress */
                        continue;
                    }
                    wire_append_uint8(out, v);
                    cursor += 3; /* consumed 3 digits */
                    continue;
                }

                /* take next byte literally */
                wire_append_uint8(out, (uint8_t)(unsigned char)e);
                cursor++;
                continue;
            }

            /* normal byte */
            wire_append_uint8(out, (uint8_t)(unsigned char)c);
            cursor++;
        }

        return cursor;
    }

    /* unquoted token: stop at “space-equivalent” */
    if (is_space_equiv(data[cursor])) {
        /* empty token is an error */
        return PARSE_ERR(1, cursor, max, out);
    }

    for (;;) {
        if (cursor > max)
            return max + 1;
        if (cursor == max)
            break;

        char c = data[cursor];
        if (is_space_equiv(c))
            break;

        if (c == '\\') {
            cursor++;
            if (cursor > max)
                return max + 1;
            if (cursor == max) {
                return PARSE_ERR(1, cursor, max, out);
                break;
            }

            char e = data[cursor];

            if (is_digit(e)) {
                uint8_t v;
                if (!parse_ddd_byte(data, cursor, max, &v)) {
                    PARSE_ERR(1, cursor, max, out);
                    cursor++;
                    continue;
                }
                wire_append_uint8(out, v);
                cursor += 3;
                continue;
            }

            wire_append_uint8(out, (uint8_t)(unsigned char)e);
            cursor++;
            continue;
        }

        wire_append_uint8(out, (uint8_t)(unsigned char)c);
        cursor++;
    }

    return cursor;
}
