/* zone-atom-base64es.c
 *
 * zone_atom_base64es()
 * -------------------
 * Decode a Base64 blob (RFC 4648, standard alphabet) that may be split across
 * whitespace and DNS zonefile multiline constructs.
 *
 * This atom is intended for records like DNSKEY, RRSIG, IPSECKEY where the
 * base64 field is often wrapped and/or split across lines inside parentheses.
 *
 * Key behavior matching your zone_parse_space() description:
 *   - ' ' and '\t' are always skippable separators.
 *   - '(' increments *depth and is a separator.
 *   - ')' decrements *depth (if >0) and is a separator.
 *   - ';' starts a comment that is skipped to '\n' regardless of depth.
 *       * If *depth == 0, this is a stopping condition for this atom.
 *       * If *depth > 0, we consume the '\n' and continue (still within a record).
 *   - '\r' and '\n':
 *       * If *depth == 0, they stop the atom (end of record).
 *       * If *depth > 0, they are treated like whitespace separators and consumed.
 *
 * Design goal: "accumulate errors, report once"
 *   - We decode using a 256-byte lookup table where invalid characters have bit
 *     0x80 set.
 *   - We OR together all decoded table outputs; if any invalid occurred, bit
 *     0x80 will be set in the accumulator.
 *   - Padding and structural errors are also accumulated and only reported once.
 *
 * Wire output:
 *   - This atom appends the decoded raw bytes to out->wire (no length prefix).
 *
 * Return / error conventions (matching your other atoms):
 *   - If cursor > max, return max+1
 *   - On error, set out->err_code=1 and out->err_cursor to the first error
 *     position (only if err_code was previously 0).
 *
 * This file also includes:
 *   - int zone_atom_base64es_quicktest(void)
 *     A deterministic pseudo-random test suite. Each testcase provides:
 *       - a base64 string (with whitespace and parens sprinkled in)
 *       - expected length (<=16)
 *       - expected first 16 decoded bytes (zero-padded)
 */

#include "zone-parse.h"
#include "zone-atom.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>



/* -------------------------------------------------------------------------- */
/* Base64 decode table                                                        */
/* -------------------------------------------------------------------------- */
/*
 * Table outputs:
 *   - 0..63  : valid sextet
 *   - 0x40   : '=' padding marker (NOT an error)
 *   - 0x80.. : invalid marker (bit 0x80 set indicates error)
 */
static const uint8_t b64dec[256] = {
#define XX 0x80
#define PD 0x40
    /* 0x00..0x0F */
    XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,
    /* 0x10..0x1F */
    XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,
    /* 0x20..0x2F   ' '  !  "  #  $  %  &  '  (  )  *  +  ,  -  .  / */
    XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,62,XX,XX,XX,63,
    /* 0x30..0x3F   0..9  :  ;  <  =  >  ? */
    52,53,54,55,56,57,58,59,60,61,XX,XX,XX,PD,XX,XX,
    /* 0x40..0x4F   @  A..O */
    XX, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
    /* 0x50..0x5F   P..Z  [ \ ] ^ _ */
    15,16,17,18,19,20,21,22,23,24,25,XX,XX,XX,XX,XX,
    /* 0x60..0x6F   `  a..o */
    XX,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
    /* 0x70..0x7F   p..z  { | } ~ DEL */
    41,42,43,44,45,46,47,48,49,50,51,XX,XX,XX,XX,XX,

    /* 0x80..0xFF all invalid */
    XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,
    XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,
    XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,
    XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,
    XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,
    XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,
    XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,
    XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX
#undef XX
#undef PD
};

/* -------------------------------------------------------------------------- */
/* Zonefile-aware skipping for base64                                         */
/* -------------------------------------------------------------------------- */

/*
 * Skip separators and multiline structure, updating *depth in-place.
 *
 * Returns:
 *   0 -> "stop": end-of-record reached (depth==0 and newline/comment ended record)
 *   1 -> "continue": cursor advanced and now points at a candidate base64 char
 *
 * Behavior mirrors your described zone_parse_space() comment/paren rules,
 * but is specialized for this atom for speed and clarity.
 */
static int
b64_skip_separators(const char *data, size_t *pcursor, size_t max, unsigned *depth,
                    uint8_t *err_accum, size_t *first_err_cursor)
{
    size_t cursor = *pcursor;

    for (;;) {
        if (cursor > max) {
            *pcursor = max + 1;
            return 0;
        }
        if (cursor == max) {
            *pcursor = cursor;
            return 0;
        }

        char c = data[cursor];

        /* Fast path: spaces/tabs */
        if (c == ' ' || c == '\t') {
            cursor++;
            continue;
        }

        /* Newlines: stop if depth==0, otherwise consume as whitespace */
        if (c == '\r' || c == '\n') {
            if (*depth == 0) {
                *pcursor = cursor;
                return 0;
            }
            cursor++;
            continue;
        }

        /* Parentheses are separators and change depth */
        if (c == '(') {
            (*depth)++;
            cursor++;
            continue;
        }
        if (c == ')') {
            if (*depth > 0) {
                (*depth)--;
            } else {
                /* unmatched ')' is an error, but keep going */
                *err_accum |= 0x80;
                if (*first_err_cursor == (size_t)(~(size_t)0))
                    *first_err_cursor = cursor;
            }
            cursor++;
            continue;
        }

        /* Comments: skip to newline always */
        if (c == ';') {
            /* Skip to '\n' or end */
            while (cursor < max && data[cursor] != '\n')
                cursor++;

            /* If depth==0, comment terminates the record for this atom */
            if (*depth == 0) {
                *pcursor = cursor; /* positioned at '\n' or max */
                return 0;
            }

            /* depth>0: consume the newline if present and continue */
            if (cursor < max && data[cursor] == '\n')
                cursor++;
            continue;
        }

        /* Otherwise: not a separator; caller should treat as base64 token */
        break;
    }

    *pcursor = cursor;
    return 1;
}

/* Fetch the next base64 token character, or stop.
 * Returns 1 and sets *out_ch if available, else returns 0 if stopped.
 */
static int
b64_next_char(const char *data, size_t *pcursor, size_t max,
              unsigned *depth, uint8_t *err_accum, size_t *first_err_cursor,
              char *out_ch)
{
    if (!b64_skip_separators(data, pcursor, max, depth, err_accum, first_err_cursor))
        return 0;

    if (*pcursor > max)
        return 0;
    if (*pcursor == max)
        return 0;

    *out_ch = data[*pcursor];
    (*pcursor)++;
    return 1;
}

/* -------------------------------------------------------------------------- */
/* The atom                                                                    */
/* -------------------------------------------------------------------------- */

size_t
zone_atom_base64a(const char *data, size_t cursor, size_t max,
                   struct wire_record_t *out, unsigned *depth)
{
    if (cursor > max)
        return max + 1;

    /* Accumulate decode-table invalids and structural/padding errors */
    uint8_t bad_or = 0;                       /* invalid character accumulator (0x80) */
    uint8_t pad_bad = 0;                      /* padding/shape errors (0x80) */
    size_t first_bad_cursor = (size_t)(~(size_t)0);

    /* Once '=' padding is seen, only '=' or separators may follow. */
    int has_seen_pad = 0;

    for (;;) {
        /* Read one 4-character quantum */
        char c0, c1, c2, c3;
        size_t pos0 = cursor;
        if (!b64_next_char(data, &cursor, max, depth, &pad_bad, &first_bad_cursor, &c0))
            break; /* no more tokens */

        size_t pos1 = cursor;
        if (!b64_next_char(data, &cursor, max, depth, &pad_bad, &first_bad_cursor, &c1)) {
            /* incomplete quantum */
            pad_bad |= 0x80;
            if (first_bad_cursor == (size_t)(~(size_t)0)) first_bad_cursor = pos1;
            break;
        }

        size_t pos2 = cursor;
        if (!b64_next_char(data, &cursor, max, depth, &pad_bad, &first_bad_cursor, &c2)) {
            pad_bad |= 0x80;
            if (first_bad_cursor == (size_t)(~(size_t)0)) first_bad_cursor = pos2;
            break;
        }

        size_t pos3 = cursor;
        if (!b64_next_char(data, &cursor, max, depth, &pad_bad, &first_bad_cursor, &c3)) {
            pad_bad |= 0x80;
            if (first_bad_cursor == (size_t)(~(size_t)0)) first_bad_cursor = pos3;
            break;
        }

        uint8_t v0 = b64dec[(unsigned char)c0];
        uint8_t v1 = b64dec[(unsigned char)c1];
        uint8_t v2 = b64dec[(unsigned char)c2];
        uint8_t v3 = b64dec[(unsigned char)c3];

        bad_or |= (uint8_t)(v0 | v1 | v2 | v3);

        /* If we've already seen padding, any non '=' token is an error. */
        if (has_seen_pad) {
            /* (We don't branch on each, we just OR a flag.) */
            pad_bad |= (uint8_t)(((v0 != 0x40) || (v1 != 0x40) || (v2 != 0x40) || (v3 != 0x40)) ? 0x80 : 0);
            if ((pad_bad & 0x80) && first_bad_cursor == (size_t)(~(size_t)0))
                first_bad_cursor = pos0;
        }

        int v2_pad = (v2 == 0x40);
        int v3_pad = (v3 == 0x40);

        /* Illegal: v2 == '=' but v3 != '=' */
        pad_bad |= (uint8_t)((v2_pad && !v3_pad) ? 0x80 : 0);
        if ((v2_pad && !v3_pad) && first_bad_cursor == (size_t)(~(size_t)0))
            first_bad_cursor = pos2;

        if (v2_pad || v3_pad)
            has_seen_pad = 1;

        /* Compute output bytes; treat '=' as 0 by masking to 0x3f. */
        {
            uint32_t a = (uint32_t)(v0 & 0x3f);
            uint32_t b = (uint32_t)(v1 & 0x3f);
            uint32_t c = (uint32_t)(v2 & 0x3f);
            uint32_t d = (uint32_t)(v3 & 0x3f);

            uint8_t o0 = (uint8_t)((a << 2) | (b >> 4));
            uint8_t o1 = (uint8_t)((b << 4) | (c >> 2));
            uint8_t o2 = (uint8_t)((c << 6) | d);

            /* Emit 1..3 bytes depending on padding */
            wire_append_uint8(out, o0);
            if (!v2_pad) {
                wire_append_uint8(out, o1);
                if (!v3_pad) {
                    wire_append_uint8(out, o2);
                }
            }
        }

        /* If padding was present, that's the end of meaningful base64 data.
         * We still allow separators; any further base64 tokens will trip seen_pad logic.
         */
    }

    /* Any invalid decode-table entry sets bit 0x80 in bad_or */
    if ((bad_or | pad_bad) & 0x80) {
        PARSE_ERR(1, cursor, max, out);
    }

    return cursor;
}

/* -------------------------------------------------------------------------- */
/* Quicktest                                                                   */
/* -------------------------------------------------------------------------- */

struct b64tc {
    const char *b64;
    size_t out_len;
    uint8_t out16[16];
};

/* These were generated from a deterministic PRNG seed (9460) and then
 * “mutated” by inserting tabs/spaces and occasional parentheses/newlines.
 * All cases decode to <= 16 bytes.
 */
static const struct b64tc b64_cases[] = {
    { "h37C\\tRW/ ffIwjSxw=\\n", 11, { 0x87, 0x7e, 0xc2, 0x45, 0x6f, 0xdf, 0x7c, 0x8c, 0x23, 0x4b, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x00 } },
    { "UBym1Q==\\n", 4, { 0x50, 0x1c, 0xa6, 0xd5, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } },
    { "5K\\tToR(\\nFIM6h8=\\n)\\n", 8, { 0xe4, 0xa4, 0xe8, 0x44, 0x52, 0x0c, 0xea, 0x1f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } },
    { "r\\t7k=\\n", 2, { 0xaf, 0xb9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } },
    { "t0\\t0o\\n", 3, { 0xb7, 0x4d, 0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } },
    { "f\\t6c=\\n", 2, { 0x7f, 0xa7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } },
    { "c\\tR9S\\n", 3, { 0x71, 0x1f, 0x52, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } },
    { "a\\tY\\n", 1, { 0x69, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } },
    { "v\\tt\\n", 1, { 0xbe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } },
    { "6w==\\n", 1, { 0xeb, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } },
    { "f\\tQ\\n", 1, { 0x7d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } },
    { "d\\tE\\n", 1, { 0x74, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } },
    { "Q\\tA\\n", 1, { 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } },
    { "pQ==\\n", 1, { 0xa5, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } },
    { "u\\tQ\\n", 1, { 0xb9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } },
    { "K\\tA\\n", 1, { 0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } },
    { "Q\\tQ\\n", 1, { 0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } },
    { "eQ==\\n", 1, { 0x79, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } },
    { "V\\tw\\n", 1, { 0x57, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } },
    { "mA==\\n", 1, { 0x98, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } },
    { "V\\tQ\\n", 1, { 0x55, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } },
    { "f\\tw\\n", 1, { 0x7f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } },
    { "q\\tQ\\n", 1, { 0xa9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } },
    { "Y\\tA\\n", 1, { 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } },
    { "Y\\tQ\\n", 1, { 0x61, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } },
};

int
zone_atom_base64a_quicktest(void)
{
    int failures = 0;

    for (size_t i = 0; i < sizeof(b64_cases) / sizeof(b64_cases[0]); i++) {
        const struct b64tc *tc = &b64_cases[i];

        uint8_t wire[64+1024];
        struct wire_record_t out;
        unsigned depth = 0;

        memset(&out, 0, sizeof(out));
        out.wire.buf = wire;
        out.wire.max = 64;

        /*
         * Run test
         */
        (void)zone_atom_base64a(tc->b64, 0, strlen(tc->b64), &out, &depth);

        if (out.err.code != 0) {
            fprintf(stderr, "base64es tc[%zu]: unexpected err_code=%u at cursor=%zu\n",
                    i, out.err.code, out.err.cursor);
            failures++;
            continue;
        }

        if (out.wire.len != tc->out_len) {
            fprintf(stderr, "base64es tc[%zu]: length mismatch got=%zu expected=%zu\n",
                    i, out.wire.len, tc->out_len);
            failures++;
            continue;
        }

        if (memcmp(out.wire.buf, tc->out16, tc->out_len) != 0) {
            fprintf(stderr, "base64es tc[%zu]: bytes mismatch (first %zu bytes)\n",
                    i, tc->out_len);
            fprintf(stderr, "  got: ");
            for (size_t k = 0; k < tc->out_len; k++)
                fprintf(stderr, "%02x", (unsigned)out.wire.buf[k]);
            fprintf(stderr, "\n  exp: ");
            for (size_t k = 0; k < tc->out_len; k++)
                fprintf(stderr, "%02x", (unsigned)tc->out16[k]);
            fprintf(stderr, "\n");
            failures++;
            continue;
        }
    }

    if (failures == 0) {
        printf("zone_atom_base64es_quicktest: OK (%zu cases)\n",
               sizeof(b64_cases) / sizeof(b64_cases[0]));
    } else {
        printf("zone_atom_base64es_quicktest: FAIL (%d failures)\n", failures);
    }

    return failures;
}

