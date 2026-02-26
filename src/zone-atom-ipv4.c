/*  zone-atom-ipv4.c
 *
 *  DNS zonefile IPv4 (A RDATA) atom parser + self-test.
 *
 *  Functions:
 *      size_t zone_atom_ipv4(const char *data, size_t cursor, size_t max,
 *                            zone_atom_t *out);
 *
 *      int zone_atom_ipv4_quicktest(void);
 *
 *  Purpose:
 *      Parse a strict dotted-decimal IPv4 address at data[cursor..max).
 *      On success, append 4 bytes (network order) to out->wire and return
 *      the updated cursor (i.e., the new cursor after the consumed bytes).
 *
 *  Strict parsing requirements (as specified):
 *    - Input is an IPv4 address in dotted-decimal form: a.b.c.d
 *    - Exactly 4 octets separated by exactly 3 dots.
 *    - Each octet is 1..3 ASCII digits and must be in [0,255].
 *    - No leading zeroes are allowed:
 *        * "0" is allowed
 *        * "00", "01", "001" are errors
 *    - The end of the IPv4 address is any character that's NOT a digit
 *      and NOT a dot. The terminating character is not consumed.
 *    - Any deviation from the above is an error.
 *
 *  DNS zonefile-specific notes / extra conservatism:
 *    - Zonefile fields are tokenized by whitespace, comment ';', newline,
 *      and also often by ')' when multiline records close. All of those are
 *      non-digit/non-dot, so they naturally terminate the address here.
 *    - We do NOT accept shorthand forms (no fewer-than-4 octets).
 *    - We do NOT accept trailing dot, consecutive dots, or embedded whitespace.
 *    - We require that after the 4th octet, the next character (if any within
 *      bounds) is NOT a digit and NOT a dot. This prevents accepting
 *      "1.2.3.4.5" or "1.2.3.45" as valid.
 *
 *  Error handling contract (updated to include error_cursor per request):
 *    - zone_atom_t (from zone-atom.h) is assumed to contain:
 *        * unsigned char *wire;
 *        * size_t wire_len;
 *        * size_t wire_max;
 *        * int error_code;
 *        * size_t error_cursor;   // index into 'data' where error detected
 *
 *    - On error:
 *        * out->error_code is set (non-zero)
 *        * out->error_cursor is set to the character index that caused the error
 *        * out->wire.len is not modified
 *        * the function returns the original cursor (consumes nothing)
 *
 *  Bounds:
 *    - The parser never reads beyond [cursor, max).
 *    - If input ends (cursor reaches max) before a valid termination character
 *      is encountered after the 4th octet, this is treated as an error because
 *      the caller contract said "end is any character that's not digit or dot".
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "zone-atom.h"
#include "zone-parse.h"
#include "zone-parse-record.h"

/* For the quicktest. If you don't want stdio in production builds, you can
 * compile this file with a flag that omits the quicktest, or adjust logging.
 */
#include <stdio.h>

#ifndef ZONE_ERR_IPV4_SYNTAX
#define ZONE_ERR_IPV4_SYNTAX        1001
#endif
#ifndef ZONE_ERR_IPV4_RANGE
#define ZONE_ERR_IPV4_RANGE         1002
#endif
#ifndef ZONE_ERR_IPV4_TRUNCATED
#define ZONE_ERR_IPV4_TRUNCATED     1003
#endif
#ifndef ZONE_ERR_NO_SPACE
#define ZONE_ERR_NO_SPACE           1004
#endif

static int is_digit_ascii(unsigned char c) {
    return (c >= (unsigned char)'0' && c <= (unsigned char)'9');
}

static int is_digit_or_dot(unsigned char c) {
    return is_digit_ascii(c) || (c == (unsigned char)'.');
}

/* Parse one octet starting at *p.
 * On success:
 *   - writes parsed value to *out_octet
 *   - advances *p to first char after the octet digits
 * On failure:
 *   - returns 0
 *   - writes *err_code and *err_cursor (best effort)
 *
 * Rules:
 *   - 1..3 digits
 *   - no leading zeros unless the octet is exactly "0"
 *   - value <= 255
 */
static int parse_octet(const char *data,
                       size_t *p, size_t max,
                       uint8_t *out_octet,
                       int *err_code,
                       size_t *err_cursor)
{
    size_t i = *p;
    unsigned char c0;
    unsigned int v = 0;
    size_t nd = 0;

    if (i >= max) {
        *err_code = ZONE_ERR_IPV4_TRUNCATED;
        *err_cursor = i;
        return 0;
    }
    c0 = (unsigned char)data[i];
    if (!is_digit_ascii(c0)) {
        *err_code = ZONE_ERR_IPV4_SYNTAX;
        *err_cursor = i;
        return 0;
    }

    /* Leading zero rule: if first digit is '0', octet must be exactly "0". */
    if (c0 == (unsigned char)'0') {
        i++;
        nd = 1;
        if (i < max && is_digit_ascii((unsigned char)data[i])) {
            /* The second digit is what makes this invalid. */
            *err_code = ZONE_ERR_IPV4_SYNTAX;
            *err_cursor = i;
            return 0;
        }
        (void)nd;
        *out_octet = 0;
        *p = i;
        return 1;
    }

    /* First digit is 1..9; read up to 3 digits total. */
    while (i < max) {
        unsigned char c = (unsigned char)data[i];
        if (!is_digit_ascii(c)) break;

        if (nd == 3) {
            /* 4th digit in this octet => error at this digit. */
            *err_code = ZONE_ERR_IPV4_SYNTAX;
            *err_cursor = i;
            return 0;
        }

        v = (v * 10u) + (unsigned int)(c - (unsigned char)'0');
        nd++;
        i++;
    }

    if (nd == 0) {
        *err_code = ZONE_ERR_IPV4_SYNTAX;
        *err_cursor = *p;
        return 0;
    }
    if (v > 255u) {
        *err_code = ZONE_ERR_IPV4_RANGE;
        /* Point at the first digit of the octet as the cause (most useful). */
        *err_cursor = *p;
        return 0;
    }

    *out_octet = (uint8_t)v;
    *p = i;
    return 1;
}

size_t zone_atom_ipv4(const char *data, size_t cursor, size_t max, struct wire_record_t *out) {
    size_t p = cursor;
    uint8_t octets[4];
    size_t wire_len_before;
    int err = 0;
    size_t err_cursor = cursor;

    if (out == NULL || data == NULL) {
        return cursor;
    }

    if (out->err.code != 0) {
        return cursor;
    }

    wire_len_before = out->wire.len;

    if (out->wire.buf == NULL || out->wire.len > out->wire.max || (out->wire.max - out->wire.len) < 4) {
        return PARSE_ERR(1, cursor, max, out);
    }

    if (!parse_octet(data, &p, max, &octets[0], &err, &err_cursor)) goto fail;

    /* Expect '.' */
    if (p >= max) { err = ZONE_ERR_IPV4_TRUNCATED; err_cursor = p; goto fail; }
    if ((unsigned char)data[p] != (unsigned char)'.') { err = ZONE_ERR_IPV4_SYNTAX; err_cursor = p; goto fail; }
    p++;

    if (!parse_octet(data, &p, max, &octets[1], &err, &err_cursor)) goto fail;

    if (p >= max) { err = ZONE_ERR_IPV4_TRUNCATED; err_cursor = p; goto fail; }
    if ((unsigned char)data[p] != (unsigned char)'.') { err = ZONE_ERR_IPV4_SYNTAX; err_cursor = p; goto fail; }
    p++;

    if (!parse_octet(data, &p, max, &octets[2], &err, &err_cursor)) goto fail;

    if (p >= max) { err = ZONE_ERR_IPV4_TRUNCATED; err_cursor = p; goto fail; }
    if ((unsigned char)data[p] != (unsigned char)'.') { err = ZONE_ERR_IPV4_SYNTAX; err_cursor = p; goto fail; }
    p++;

    if (!parse_octet(data, &p, max, &octets[3], &err, &err_cursor))
        goto fail;

    /* Require a terminating non-digit/non-dot character within bounds. */
    if (p >= max) {
        err = ZONE_ERR_IPV4_TRUNCATED;
        err_cursor = p;
        goto fail;
    }
    if (is_digit_or_dot((unsigned char)data[p])) {
        err = ZONE_ERR_IPV4_SYNTAX;
        err_cursor = p;
        goto fail;
    }

    out->wire.buf[out->wire.len + 0] = (unsigned char)octets[0];
    out->wire.buf[out->wire.len + 1] = (unsigned char)octets[1];
    out->wire.buf[out->wire.len + 2] = (unsigned char)octets[2];
    out->wire.buf[out->wire.len + 3] = (unsigned char)octets[3];
    out->wire.len += 4;

    return p;

fail:
    return PARSE_ERR(ZONE_ERR_IPV4_SYNTAX, cursor, max, out);
}

/* Quick self-test. Returns 0 on success, non-zero on failure.
 *
 * Notes:
 *  - We use max = strlen(input) for each test (i.e., the full buffer),
 *    and ensure inputs include a terminating non-digit/non-dot delimiter
 *    on success cases (space, ';', '\n', ')', etc.) as required by the parser.
 *  - We verify:
 *      * success/fail
 *      * parsed 4 bytes (on success)
 *      * returned cursor equals expected consumed length (on success)
 *      * error_code and error_cursor (on failure)
 */
int zone_atom_ipv4_quicktest(void) {
    struct tc {
        const char *in;
        size_t cursor;
        int should_succeed;

        /* Success expectations */
        uint8_t expect[4];
        size_t expect_new_cursor;

        /* Failure expectations */
        int expect_err;
        size_t expect_err_cursor;
    };

    static const struct tc tests[] = {
        /* --- Success cases --- */
        { "0.0.0.0 ",   0, 1, {0,0,0,0},   7, 0, 0 },
        { "1.2.3.4;",   0, 1, {1,2,3,4},   7, 0, 0 },
        { "255.255.255.255\n", 0, 1, {255,255,255,255}, 15, 0, 0 },
        { "10.0.0.1)",  0, 1, {10,0,0,1},  8, 0, 0 },
        { "  192.168.1.10 ", 2, 1, {192,168,1,10}, 2 + 12, 0, 0 },

        /* --- Failure cases: leading zeros --- */
        /* "01" => error at index 1 (the '1' that makes it invalid) */
        { "01.2.3.4 ",  0, 0, {0,0,0,0}, 0, ZONE_ERR_IPV4_SYNTAX, 1 },
        { "1.02.3.4 ",  0, 0, {0,0,0,0}, 0, ZONE_ERR_IPV4_SYNTAX, 3 }, /* '2' in "02" */
        { "1.2.003.4 ", 0, 0, {0,0,0,0}, 0, ZONE_ERR_IPV4_SYNTAX, 5 }, /* second '0' after first '0' in 003 */

        /* --- Failure cases: range --- */
        { "256.0.0.1 ", 0, 0, {0,0,0,0}, 0, ZONE_ERR_IPV4_RANGE,  0 }, /* first digit of '256' */
        { "1.2.3.999 ", 0, 0, {0,0,0,0}, 0, ZONE_ERR_IPV4_RANGE,  6 }, /* start of '999' */

        /* --- Failure cases: syntax / structure --- */
        { "1.2.3 ",     0, 0, {0,0,0,0}, 0, ZONE_ERR_IPV4_SYNTAX,  5 }, /* expected '.' at space */
        { "1.2.3. ",    0, 0, {0,0,0,0}, 0, ZONE_ERR_IPV4_SYNTAX,  6 }, /* 4th octet missing, space where digit expected */
        { "1..3.4 ",    0, 0, {0,0,0,0}, 0, ZONE_ERR_IPV4_SYNTAX,  2 }, /* second '.' where digit expected */
        { "1.2.3.4.5 ", 0, 0, {0,0,0,0}, 0, ZONE_ERR_IPV4_SYNTAX,  7 }, /* dot after 4th octet is forbidden */
        { "1.2.3.45 ",  0, 0, {0,0,0,0}, 0, ZONE_ERR_IPV4_SYNTAX,  7 }, /* digit after 4th octet is forbidden */
        { "1234.1.2.3 ",0, 0, {0,0,0,0}, 0, ZONE_ERR_IPV4_SYNTAX,  3 }, /* 4th digit in octet */
        { "1.2.3.4",    0, 0, {0,0,0,0}, 0, ZONE_ERR_IPV4_TRUNCATED, 7 }, /* no terminator within max */

        /* --- Failure cases: truncated mid-parse --- */
        { "1.2.3.",     0, 0, {0,0,0,0}, 0, ZONE_ERR_IPV4_TRUNCATED, 6 }, /* ended where 4th octet should begin */
        { "1.2.3.4",    0, 0, {0,0,0,0}, 0, ZONE_ERR_IPV4_TRUNCATED, 7 }, /* ended right after 4th octet */
    };

    int failures = 0;
    size_t i;

    for (i = 0; i < (sizeof(tests) / sizeof(tests[0])); i++) {
        const struct tc *t = &tests[i];
        size_t max = strlen(t->in);
        size_t new_cursor;
        int ok = 1;

        /* Init out */
        unsigned char wirebuf[16+1024];
        wire_record_t out = {0};
        out.wire.buf = wirebuf;
        out.wire.max = 16;
 
        new_cursor = zone_atom_ipv4(t->in, t->cursor, max, &out);

        if (t->should_succeed) {
            if (out.err.code != 0) ok = 0;
            if (new_cursor != t->expect_new_cursor) ok = 0;
            if (out.wire.len != 4) ok = 0;
            if (out.wire.len == 4) {
                if (wirebuf[0] != t->expect[0] ||
                    wirebuf[1] != t->expect[1] ||
                    wirebuf[2] != t->expect[2] ||
                    wirebuf[3] != t->expect[3]) {
                    ok = 0;
                }
            }
        } else {
            if (out.err.code == 0) ok = 0;
            if (new_cursor != t->cursor) ok = 0;
            if (out.wire.len != 0) ok = 0;
            if (out.err.code != t->expect_err) ok = 0;
            if (out.err.cursor != t->expect_err_cursor) ok = 0;
        }

        if (!ok) {
            failures++;
            fprintf(stderr,
                    "zone_atom_ipv4_quicktest: FAIL test #%zu\n"
                    "  input: \"%s\" (cursor=%zu, max=%zu)\n"
                    "  got: new_cursor=%zu wire_len=%zu err=%d err_cursor=%zu\n",
                    i,
                    t->in, t->cursor, max,
                    new_cursor, out.wire.len, out.err.code, out.err.cursor);

            if (t->should_succeed) {
                fprintf(stderr,
                        "  expected: new_cursor=%zu wire=[%u,%u,%u,%u] err=0\n",
                        t->expect_new_cursor,
                        (unsigned)t->expect[0], (unsigned)t->expect[1],
                        (unsigned)t->expect[2], (unsigned)t->expect[3]);
            } else {
                fprintf(stderr,
                        "  expected: new_cursor=%zu wire_len=0 err=%d err_cursor=%zu\n",
                        t->cursor, t->expect_err, t->expect_err_cursor);
            }
        }
    }

    if (failures == 0) {
        fprintf(stderr, "zone_atom_ipv4_quicktest: OK (%zu tests)\n",
                (sizeof(tests) / sizeof(tests[0])));
    }

    return failures;
}
