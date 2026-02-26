

/*
 * zone_atom_expiry()
 *
 * Parse an “expiry”/timestamp field.
 *
 * If the next token is exactly 14 digits, interpret it as:
 *   YYYYMMDDHHMMSS
 * and convert to a 32-bit unsigned “seconds since Unix epoch” (UTC),
 * then append as uint32 to the wire.
 *
 * Otherwise, fall back to zone_atom_int32() (decimal seconds value).
 *
 * Notes:
 *  - This is intended for fields like RRSIG inception/expiration.
 *  - It measures the token length without consuming trailing whitespace.
 *  - On invalid 14-digit date/time, sets out->err_code/out->err_cursor and
 *    still appends a uint32 (0) to keep cursor progress consistent.
 *
 * Assumes available in this file already:
 *   - is_digit(char)
 *   - size_t zone_atom_int32(...)
 *   - void wire_append_uint32(struct wire_record_t *out, uint32_t v, int *err);
 *   - set_err_once(out, cursor) helper (or equivalent logic)
 *
 * If you don't have wire_append_uint32(), you can replace it with four uint8 appends.
 */
#include "zone-atom.h"
#include <stdint.h>
#include <stddef.h>



static int
is_leap_year(unsigned y)
{
    /* Gregorian calendar */
    return (y % 4u == 0u) && ((y % 100u != 0u) || (y % 400u == 0u));
}

static unsigned
days_in_month(unsigned y, unsigned m)
{
    static const unsigned mdays[12] = {
        31,28,31,30,31,30,31,31,30,31,30,31
    };
    if (m == 2 && is_leap_year(y))
        return 29;
    return mdays[m - 1];
}

static uint32_t
ymdhms_to_epoch(unsigned Y, unsigned M, unsigned D,
                unsigned h, unsigned m, unsigned s,
                size_t cursor, size_t max, struct wire_record_t *out) {
    int err = 0;
    
    /* Validate ranges conservatively */
    err |= (Y < 1970u || Y > 2106u); /* 2106-02-07 is near uint32 wrap */
    err |= (M < 1u || M > 12u);
    unsigned dim = days_in_month(Y, M);
    err |= (D < 1u || D > dim);
    err |= (h > 23u);
    err |= (m > 59u);
    err |= (s > 60u);
    
    /* Compute days since 1970-01-01 */
    uint64_t days = 0;

    for (unsigned y = 1970u; y < Y; y++)
        days += is_leap_year(y) ? 366u : 365u;

    for (unsigned mon = 1u; mon < M; mon++)
        days += days_in_month(Y, mon);

    days += (uint64_t)(D - 1u);

    uint64_t secs = days * 86400ull + (uint64_t)h * 3600ull + (uint64_t)m * 60ull + (uint64_t)s;

    err |= (secs > 0xFFFFFFFFull);
    
    if (err)
        PARSE_ERR(1, cursor, max, out);

    return (uint32_t)secs;
}

static inline int is_digit(char c) {
    return (c >= (unsigned char)'0' && c <= (unsigned char)'9');
}

size_t
zone_atom_expire1(const char *data, size_t cursor, size_t max,
                 struct wire_record_t *out)
{
    if (cursor > max)
        return max + 1;

    /* Measure token length: digits only */
    size_t start = cursor;
    size_t n = 0;
    while (cursor < max && is_digit(data[cursor])) {
        cursor++;
        n++;
        if (n > 14)
            break;
    }

    /* Exactly 14 digits => parse YYYYMMDDHHMMSS */
    if (n == 14) {
        /* Parse components without branching a lot: digit math */
        const char *p = data + start;

        unsigned Y = (unsigned)(p[0]-'0')*1000u + (unsigned)(p[1]-'0')*100u +
                     (unsigned)(p[2]-'0')*10u   + (unsigned)(p[3]-'0');
        unsigned M = (unsigned)(p[4]-'0')*10u   + (unsigned)(p[5]-'0');
        unsigned D = (unsigned)(p[6]-'0')*10u   + (unsigned)(p[7]-'0');
        unsigned h = (unsigned)(p[8]-'0')*10u   + (unsigned)(p[9]-'0');
        unsigned m = (unsigned)(p[10]-'0')*10u  + (unsigned)(p[11]-'0');
        unsigned s = (unsigned)(p[12]-'0')*10u  + (unsigned)(p[13]-'0');

        uint32_t epoch = ymdhms_to_epoch(Y, M, D, h, m, s, start, max, out);

        wire_append_uint32(out, epoch);

        return start + 14;
    }

    /* Not 14 digits: fall back to int32 parsing.
     * IMPORTANT: We must call with the original cursor, not the advanced one.
     */
    return zone_atom_int32(data, start, max, out);
}
