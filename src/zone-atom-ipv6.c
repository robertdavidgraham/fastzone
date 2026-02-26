/*
 * zone-atom-ipv6.c  (portable C11, MSVC/GCC/Clang)
 *
 * Fast, readable IPv6 text parser supporting:
 *   - normal hextets
 *   - "::" compression
 *   - embedded IPv4 tail (e.g. ::ffff:192.0.2.1)
 *
 * Token termination:
 *   Parsing stops when the next character is not in [0-9A-Fa-f], ':' or '.'
 *   (caller decides what ends the field).
 *
 * API:
 *   size_t zone_atom_ipv6(const char *data, size_t cursor, size_t max, wire_record_t *out);
 *
 * Success:
 *   Appends 16 bytes to out->wire (network order), updates out->wire.len,
 *   returns advanced cursor.
 *
 * Failure:
 *   Sets out->err_code and out->err_cursor, returns original cursor.
 *
 * Notes:
 *   - No designated initializers (MSVC-friendly).
 *   - No C++ features.
 *   - Correctly handles IPv4 tail placement at the END of the IPv6 address,
 *     including when "::" compression is present. The "::" expansion is
 *     performed at the end, leaving room for any already-parsed tail parts.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>

#include "zone-atom.h" /* wire_record_t: wire, wire_len, wire_max, err_code, err_cursor */

#ifndef ZONE_ERR_NONE
#define ZONE_ERR_NONE            0
#endif
#ifndef ZONE_ERR_IPV6_SYNTAX
#define ZONE_ERR_IPV6_SYNTAX     2001
#endif
#ifndef ZONE_ERR_IPV6_OVERFLOW
#define ZONE_ERR_IPV6_OVERFLOW   2002
#endif
#ifndef ZONE_ERR_WIRE_TOO_SMALL
#define ZONE_ERR_WIRE_TOO_SMALL  2003
#endif



static int zone_is_digit_u8(unsigned char c)
{
    return (c >= (unsigned char)'0' && c <= (unsigned char)'9');
}

/* Returns 0..15 for hex digit; 0xFF otherwise. (No lookup tables; MSVC-safe) */
static unsigned char zone_hexval_u8(unsigned char c)
{
    /* digit path */
    unsigned d = (unsigned)(c - (unsigned char)'0');
    if (d <= 9u) return (unsigned char)d;

    /* fold ASCII A-F to a-f */
    c = (unsigned char)(c | 0x20u);
    d = (unsigned)(c - (unsigned char)'a');
    if (d <= 5u) return (unsigned char)(10u + d);

    return 0xFFu;
}

static int zone_is_ipv6_char(unsigned char c)
{
    /* Used only for token termination */
    return (zone_hexval_u8(c) != 0xFFu) || (c == (unsigned char)':') || (c == (unsigned char)'.');
}

/* Parse a decimal byte 0..255 with no leading zeros unless exactly "0". */
static size_t zone_parse_ipv4_octet(const char *data, size_t cur, size_t max,
                                    unsigned char *outv, int *ok)
{
    size_t start = cur;
    unsigned v;

    if (cur >= max || !zone_is_digit_u8((unsigned char)data[cur])) {
        *ok = 0;
        return start;
    }

    v = (unsigned)((unsigned char)data[cur] - (unsigned char)'0');
    cur++;

    /* leading zero rule */
    if (v == 0u) {
        if (cur < max && zone_is_digit_u8((unsigned char)data[cur])) {
            *ok = 0;
            return start;
        }
        *outv = 0;
        *ok = 1;
        return cur;
    }

    /* up to two more digits */
    if (cur < max && zone_is_digit_u8((unsigned char)data[cur])) {
        v = v * 10u + (unsigned)((unsigned char)data[cur] - (unsigned char)'0');
        cur++;
        if (cur < max && zone_is_digit_u8((unsigned char)data[cur])) {
            v = v * 10u + (unsigned)((unsigned char)data[cur] - (unsigned char)'0');
            cur++;
        }
    }

    if (v > 255u) {
        *ok = 0;
        return start;
    }

    *outv = (unsigned char)v;
    *ok = 1;
    return cur;
}

static size_t zone_parse_ipv4_tail(const char *data, size_t cur, size_t max,
                                   unsigned char out4[4], int *ok)
{
    size_t start = cur;
    int good;
    unsigned char b;
    int i;

    for (i = 0; i < 4; i++) {
        cur = zone_parse_ipv4_octet(data, cur, max, &b, &good);
        if (!good) {
            *ok = 0;
            return start;
        }
        out4[i] = b;

        if (i != 3) {
            if (cur >= max || data[cur] != '.') {
                *ok = 0;
                return start;
            }
            cur++;
        }
    }

    *ok = 1;
    return cur;
}

/*
 * Parse an IPv6 address token and append 16 bytes to out->wire.
 *
 * Core approach:
 *  - Parse into uint16_t parts[8] in order, counting n_parts.
 *  - Track compress_pos for "::" (index in parts[] where zeros will be inserted).
 *  - IPv4 tail (a.b.c.d) contributes TWO uint16_t parts (last 32 bits).
 *  - At end:
 *      * If "::" present, expand by inserting (8 - n_parts) zeros at compress_pos.
 *      * If no "::", require n_parts == 8.
 *  - Emit as 16 bytes network order.
 */
size_t zone_atom_ipv6(const char *data, size_t cursor, size_t max, wire_record_t *out)
{
    size_t start = cursor;
    uint16_t parts[8];
    unsigned n_parts = 0;
    int compress_pos = -1; /* -1 means no "::" */
    int need_more = 1;

    if (data == NULL || out == NULL) return start;

    
    if (out->wire.len + 16 > out->wire.max) {
        return PARSE_ERR(1, cursor, max, out);
    }

    /* Special-case leading "::" or leading ":" error */
    if (cursor < max && data[cursor] == ':') {
        if ((cursor + 1) < max && data[cursor + 1] == ':') {
            compress_pos = 0;
            cursor += 2;
            /* "::" alone is valid; may terminate immediately */
        } else {
            return PARSE_ERR(1, cursor, max, out);
        }
    }

    while (need_more && cursor < max) {
        unsigned char ch = (unsigned char)data[cursor];

        if (!zone_is_ipv6_char(ch)) break; /* token termination */

        /* A ':' here must be a "::" (because normal separators are consumed after a part) */
        if (ch == ':') {
            if ((cursor + 1) < max && data[cursor + 1] == ':' && compress_pos < 0) {
                compress_pos = (int)n_parts;
                cursor += 2;
                /* "::" at end is okay */
                if (cursor >= max) break;
                continue;
            }
            return PARSE_ERR(1, cursor, max, out);
        }

        /* IPv4 tail detection: if digits then '.' before next ':' */
        if (zone_is_digit_u8(ch)) {
            size_t p = cursor;
            int saw_dot = 0;

            while (p < max) {
                unsigned char c = (unsigned char)data[p];
                if (c == '.') { saw_dot = 1; break; }
                if (c == ':') break;
                if (!zone_is_digit_u8(c)) break;
                p++;
            }

            if (saw_dot) {
                unsigned char v4[4];
                int ok;
                size_t cur2 = zone_parse_ipv4_tail(data, cursor, max, v4, &ok);
                if (!ok) {
                    return PARSE_ERR(1, cursor, max, out);
                }

                /* IPv4 tail is two parts; must fit */
                if (n_parts + 2u > 8u) {
                    return PARSE_ERR(1, cursor, max, out);
                }

                parts[n_parts + 0] = (uint16_t)(((uint16_t)v4[0] << 8) | (uint16_t)v4[1]);
                parts[n_parts + 1] = (uint16_t)(((uint16_t)v4[2] << 8) | (uint16_t)v4[3]);
                n_parts += 2;

                cursor = cur2;
                /* IPv4 tail must end the IPv6 token */
                need_more = 0;
                break;
            }
        }

        /* Parse 1..4 hex digits into a 16-bit value */
        {
            unsigned v = 0;
            unsigned nd = 0;

            while (cursor < max && nd < 4) {
                unsigned char hv = zone_hexval_u8((unsigned char)data[cursor]);
                if (hv == 0xFFu) break;
                v = (v << 4) | (unsigned)hv;
                nd++;
                cursor++;
            }

            if (nd == 0) {
                return PARSE_ERR(1, cursor, max, out);
            }

            if (n_parts >= 8u) {
                return PARSE_ERR(1, cursor, max, out);
            }
            parts[n_parts++] = (uint16_t)v;
        }

        /* Optional separator */
        if (cursor < max && data[cursor] == ':') {
            /* "::" only once */
            if ((cursor + 1) < max && data[cursor + 1] == ':') {
                if (compress_pos >= 0) {
                    return PARSE_ERR(1, cursor, max, out);
                }
                compress_pos = (int)n_parts;
                cursor += 2;
                continue;
            }

            cursor++;
            continue;
        }

        /* Otherwise end of token */
        break;
    }

    /* Validate + expand "::" if present */
    if (compress_pos < 0) {
        if (n_parts != 8u) {
            return PARSE_ERR(1, cursor, max, out);
        }
    } else {
        /* "::" must expand to at least one 16-bit zero if the address isn't already full */
        if (n_parts > 8u) {
            return PARSE_ERR(1, cursor, max, out);
        }

        {
            unsigned missing = 8u - n_parts; /* number of zero parts to insert */
            unsigned i;

            /* Shift tail to the right to make room (only if there's a tail) */
            /* tail_len = n_parts - compress_pos */
            if (missing > 0u) {
                /* Move from end toward compress_pos */
                for (i = n_parts; i > (unsigned)compress_pos; i--) {
                    parts[i + missing - 1u] = parts[i - 1u];
                }
                /* Fill inserted zeros */
                for (i = 0; i < missing; i++) {
                    parts[(unsigned)compress_pos + i] = 0;
                }
                n_parts = 8u;
            } else {
                /* missing == 0: address already has 8 parts; "::" would be redundant but legal only if it
                 * does not imply inserting zeros. In practice, forms like "1:2:3:4:5:6:7:8::" are invalid.
                 * Our parser would have n_parts==8 and compress_pos would have been recorded; treat as syntax error.
                 */
                return PARSE_ERR(1, cursor, max, out);
            }
        }
    }

    /* Emit 16 bytes in network order */
    {
        unsigned char bytes[16];
        unsigned i;

        for (i = 0; i < 8u; i++) {
            uint16_t v = parts[i];
            bytes[i * 2u + 0u] = (unsigned char)(v >> 8);
            bytes[i * 2u + 1u] = (unsigned char)(v & 0xFFu);
        }

        memcpy(out->wire.buf + out->wire.len, bytes, 16);
        out->wire.len += 16;
    }

    return cursor;
}

/* -------------------------------------------------------------------------- */
/* Quicktest                                                                   */
/* -------------------------------------------------------------------------- */

/*
 * zone_atom_ipv6_quicktest()
 *
 * Testcases are:
 *   { expected_hi_u64, expected_lo_u64, "ipv6-text " }
 *
 * Notes:
 *  - The input strings end with a space. The parser should stop before the space.
 *  - We validate:
 *      * out->err_code == 0 (success)
 *      * 16 output bytes match expected (two u64s, big-endian order)
 *  - If parsing fails, print a message.
 *  - If bytes mismatch, print:
 *        case#, expected as 16 hex bytes, and the original string.
 *
 * Return:
 *   number of failures (0 means all pass)
 */
int zone_atom_ipv6_quicktest(void)
{
    struct testcase {
        uint64_t hi;
        uint64_t lo;
        const char *s;
    };

    static const struct testcase tc[20] = {
        { 0x0000000000000000ULL, 0x0000000000000000ULL, ":: " },
        { 0x0000000000000000ULL, 0x0000000000000001ULL, "::1 " },
        { 0x0000000000000000ULL, 0x000000000000000fULL, "::f " },

        { 0x20010db800000000ULL, 0x0000000000000001ULL, "2001:0db8:0000:0000:0000:0000:0000:0001 " },
        { 0x20010db800000000ULL, 0x0000000000000001ULL, "2001:db8::1 " },
        { 0x20010db800010000ULL, 0x0000000000000001ULL, "2001:db8:1::1 " },
        { 0x20010db800000000ULL, 0x0000000000000000ULL, "2001:db8:: " },

        { 0x0000000000000000ULL, 0x0000000000000042ULL, "::42 " },
        { 0xffffffffffffffffULL, 0xffffffffffffffffULL, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff " },
        { 0x20010db800000000ULL, 0x00000000000000abULL, "2001:DB8::00aB " },

        { 0x0000000000000000ULL, 0x0000000000001234ULL, "::1234 " },
        { 0x0000000000000000ULL, 0x000000000000000aULL, "::000a " },

        { 0xfe80000000000000ULL, 0x0000000000000001ULL, "fe80::1 " },
        { 0xff02000000000000ULL, 0x0000000000000001ULL, "ff02::1 " },

        { 0x0001000200030004ULL, 0x0005000600070008ULL, "1:2:3:4:5:6:7:8 " },
        { 0x1234000000000000ULL, 0x00000000000000ffULL, "1234::ff " },
        { 0x1234000000000000ULL, 0x000000000000abcdULL, "1234::abcd " },

        /* Embedded IPv4 tail must occupy the LAST 32 bits */
        { 0x0000000000000000ULL, 0x0000ffffc0000280ULL, "::ffff:192.0.2.128 " },
        { 0x0000000000000000ULL, 0x00000000c0000201ULL, "::192.0.2.1 " },

        /* Terminator behavior: stops at space */
        { 0x20010db800000000ULL, 0x0000000000000001ULL, "2001:db8::1 " }
    };

    int err = 0;
    int i;

    for (i = 0; i < 20; i++) {
        size_t cur;
        size_t slen;

        /*
         * Initialize 'out' parameter
         */
        unsigned char wire[16 + 1024];
        wire_record_t out = {0};
        out.wire.buf = wire;
        out.wire.max = 16;

        slen = strlen(tc[i].s);
        cur = zone_atom_ipv6(tc[i].s, 0, slen, &out);

        if (out.err.code != 0) {
            printf("ipv6_quicktest: case %d parse error err_code=%d err_cursor=%" PRIuPTR " input=\"%s\"\n",
                   i + 1, out.err.code, (uintptr_t)out.err.cursor, tc[i].s);
            err++;
            continue;
        }

        if (out.wire.len != 16) {
            printf("ipv6_quicktest: case %d wrong output length %u input=\"%s\"\n",
                   i + 1, (unsigned)out.wire.len, tc[i].s);
            err++;
            continue;
        }

        if (cur >= slen || tc[i].s[cur] != ' ') {
            printf("ipv6_quicktest: case %d cursor did not stop at space cur=%u input=\"%s\"\n",
                   i + 1, (unsigned)cur, tc[i].s);
            err++;
            continue;
        }

        {
            uint64_t got_hi, got_lo;

            got_hi =
                ((uint64_t)wire[0] << 56) | ((uint64_t)wire[1] << 48) |
                ((uint64_t)wire[2] << 40) | ((uint64_t)wire[3] << 32) |
                ((uint64_t)wire[4] << 24) | ((uint64_t)wire[5] << 16) |
                ((uint64_t)wire[6] <<  8) | ((uint64_t)wire[7] <<  0);

            got_lo =
                ((uint64_t)wire[8]  << 56) | ((uint64_t)wire[9]  << 48) |
                ((uint64_t)wire[10] << 40) | ((uint64_t)wire[11] << 32) |
                ((uint64_t)wire[12] << 24) | ((uint64_t)wire[13] << 16) |
                ((uint64_t)wire[14] <<  8) | ((uint64_t)wire[15] <<  0);

            if (got_hi != tc[i].hi || got_lo != tc[i].lo) {
                printf("ipv6_quicktest: case %d mismatch\n", i + 1);
                printf("  expected: %016" PRIx64 "%016" PRIx64 "\n", tc[i].hi, tc[i].lo);
                printf("       got: %016" PRIx64 "%016" PRIx64 "\n", got_hi, got_lo);
                printf("  input:    \"%s\"\n", tc[i].s);
                err++;
            }
        }
    }

    if (err != 0) {
        printf("ipv6_quicktest: FAIL (%d failures)\n", err);
    } else {
        printf("ipv6_quicktest: PASS\n");
    }

    return err;
}
