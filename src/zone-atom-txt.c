
#include "zone-atom.h"
#include "zone-parse.h"
#include "zone-parse-record.h"
#include "zone-error.h"

/*
 * TXT atoms adjusted to your zone_atom_int16() style + requested changes:
 *  - Provide our own is_digit()
 *  - txt_list takes (unsigned *depth) and uses zone_parse_space() between strings
 *  - After the last txt string, we call zone_parse_space() once more and KEEP it
 *    (no rollback logic)
 *
 * Assumed project helpers exist:
 *   size_t zone_parse_space(const char *data, size_t cursor, size_t max,
 *                           struct wire_record_t *out, unsigned *depth);
 *   void wire_append_uint8(struct wire_record_t *out, uint8_t v, int *err);
 *   void wire_append_bytes(struct wire_record_t *out, const void *p, size_t n, int *err);
 *
 * Wire format for each <character-string>: <len:1> <len bytes>, len 0..255.
 */

#include <stddef.h>
#include <stdint.h>

static int
is_digit(char c)
{
    return c >= '0' && c <= '9';
}

static int
is_space_or_tab(char c)
{
    return c == ' ' || c == '\t';
}

static int
is_delim_for_txt(char c)
{
    /* end-of-token / “not part of an unquoted string” */
    return c == '\0' || c == '\r' || c == '\n' || c == ';' || c == '(' || c == ')' || is_space_or_tab(c);
}

static int
parse_ddd_byte(const char *data, size_t cursor, size_t max, uint8_t *out_byte)
{
    /* need three digits starting at cursor */
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
 * zone_atom_txt()
 * Parse exactly one <character-string> and append as <len><bytes>.
 *
 * Typical values:
 *   "hello world"
 *   v=spf1
 *   ip4:192.0.2.0/24
 *   "v=spf1 ip4:192.0.2.0/24 -all"
 */
size_t
zone_atom_txt(const char *data, size_t cursor, size_t max,
              struct wire_record_t *out)
{
    unsigned char buf[256];
    unsigned len = 0;

    if (cursor >= max)
        return max + 1;

    /* Allow an empty string maybe?
     * TODO: test this against real data */
    if (cursor == max) {
        wire_append_uint8(out, 0);
        return cursor;
    }

    /*
     * Quoted string
     */
    if (data[cursor] == '"') {
        /* quoted string */
        cursor++; /* consume opening quote */

        for (;;) {
            if (cursor >= max)
                return PARSE_ERR(ZONE_ERROR_TEXT_MISSING_QUOTES, cursor, max, out);
            
            char c = data[cursor];

            /*
             * Handle end of string
             */
            if (c == '"') {
                cursor++; /* consume closing quote */
                break;
            }

            /*
             * Handle escape
             */
            if (c == '\\') {
                cursor++;
                
                char e = data[cursor];

                if (is_digit(e)) {
                    uint8_t v;
                    if (!parse_ddd_byte(data, cursor, max, &v)) {
                        PARSE_ERR(ZONE_ERROR_ESCAPE_BAD, cursor, max, out);
                        cursor++; /* consume something and continue */
                        continue;
                    }
                    if (len >= 255) {
                        PARSE_ERR(ZONE_ERROR_TEXT_LONG, cursor, max, out);
                    } else {
                        buf[len++] = (unsigned char)v;
                    }
                    cursor += 3;
                    continue;
                }

                /* take next byte literally */
                if (len >= 255) {
                    PARSE_ERR(ZONE_ERROR_TEXT_LONG, cursor, max, out);
                } else {
                    buf[len++] = (unsigned char)e;
                }
                cursor++;
                continue;
            }

            if (len >= 255) {
                PARSE_ERR(ZONE_ERROR_TEXT_LONG, cursor, max, out);
            } else {
                buf[len++] = (unsigned char)c;
            }
            cursor++;
        }
    } else {
        /* unquoted token */
        for (;;) {
            if (cursor > max)
                return max + 1;
            if (cursor == max)
                break;

            char c = data[cursor];
            if (is_delim_for_txt(c))
                break;

            if (c == '\\') {
                cursor++;

                char e = data[cursor];

                if (is_digit(e)) {
                    uint8_t v;
                    if (!parse_ddd_byte(data, cursor, max, &v)) {
                        PARSE_ERR(ZONE_ERROR_ESCAPE_BAD, cursor, max, out);
                        cursor++;
                        continue;
                    }
                    if (len >= 255) {
                        PARSE_ERR(ZONE_ERROR_TEXT_LONG, cursor, max, out);
                    } else {
                        buf[len++] = (unsigned char)v;
                    }
                    cursor += 3;
                    continue;
                }

                if (len >= 255) {
                    PARSE_ERR(ZONE_ERROR_TEXT_LONG, cursor, max, out);
                } else {
                    buf[len++] = (unsigned char)e;
                }
                cursor++;
                continue;
            }

            if (len >= 255) {
                PARSE_ERR(ZONE_ERROR_TEXT_LONG, cursor, max, out);            } else {
                buf[len++] = (unsigned char)c;
            }
            cursor++;
        }

        if (len == 0) {
            PARSE_ERR(ZONE_ERROR_TEXT_LONG, cursor, max, out);
        }
    }

    /* emit <len><bytes> */
    wire_append_uint8(out, (uint8_t)len);
    if (len)
        wire_append_bytes(out, buf, len);

    return cursor;
}

/*
 * zone_atom_txt_list()
 * Parse one-or-more <character-string> tokens, using zone_parse_space()
 * to move between them. After parsing the last string, we call
 * zone_parse_space() one more time and keep it (no rollback).
 *
 * Typical values:
 *   "hello" "world"
 *   "v=spf1 ip4:192.0.2.0/24" "-all"
 */
size_t
zone_atom_txt_list(const char *data, size_t cursor, size_t max,
                   struct wire_record_t *out, unsigned *depth)
{
    if (cursor > max)
        return max + 1;

    /* first string is required */
    cursor = zone_atom_txt(data, cursor, max, out);

    for (;;) {
        if (cursor > max)
            return max + 1;

        /* move past whitespace/comments/paren logic */
        cursor = zone_parse_space(data, cursor, max, out, depth);
        if (cursor > max)
            return max + 1;

        if (cursor == max)
            break;

        /* if next token cannot start a character-string, stop */
        {
            char c = data[cursor];

            /* these start “non-strings” in your grammar; stop here */
            if (c == '\r' || c == '\n' || c == ';' || c == '(' || c == ')')
                break;

            /* delimiter also means no next string */
            if (is_delim_for_txt(c))
                break;
        }

        /* parse another string */
        cursor = zone_atom_txt(data, cursor, max, out);
    }

    /* per request: keep moving forward after the last string */
    cursor = zone_parse_space(data, cursor, max, out, depth);
    return cursor;
}
