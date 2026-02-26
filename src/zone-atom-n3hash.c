/* zone-atom-n3hash.c
 *
 * zone_atom_nsec3_hash()
 * ----------------------
 * Parse the “Next Hashed Owner Name” field in an NSEC3 record.
 *
 * NSEC3 presentation format (RFC 5155) uses Base32hex (RFC 4648 "base32hex")
 * without padding, typically uppercase but case-insensitive:
 *   0-9 A-V
 *
 * This atom decodes that Base32hex text into raw bytes and appends them to
 * the wire (no length prefix). The “hash length” byte that precedes this
 * field in NSEC3 wire format is expected to be handled by the TYPE parser
 * (or another atom) — this function only writes the hash bytes.
 *
 * Zonefile whitespace/comments/parentheses:
 *   - The hash is a single token (no internal spaces).
 *   - We still call zone_parse_space() first to position at the token start.
 *   - We stop decoding at the first delimiter (space/tab/CR/LF/';'/'('/')').
 *
 * Error handling:
 *   - If cursor > max: return max+1
 *   - Accumulate errors while decoding and set out->err_code once at the end.
 *     Invalid characters are marked by high bit (0x80) in the decode table.
 *   - Also treat an incomplete final 5-bit group (i.e., leftover bits not
 *     forming a whole byte) as an error, unless they are exactly zero.
 *
 * Assumed external helpers (declared in zone-parse.h / zone-atom.h):
 *   - size_t zone_parse_space(const char *data, size_t cursor, size_t max,
 *                             struct wire_record_t *out, unsigned *depth);
 *   - void wire_append_uint8(struct wire_record_t *out, uint8_t v, int *err);
 */
/* zone-atom-n3hash.c
 *
 * zone_atom_nsec3_hash()
 * ----------------------
 * Parse the NSEC3 “Next Hashed Owner Name” field (RFC 5155).
 *
 * Presentation format:
 *   - Base32hex (RFC 4648 "base32hex"), no padding, case-insensitive:
 *       alphabet: 0-9 A-V
 *   - In zonefiles this appears as a single token.
 *
 * Wire format for this field in NSEC3 RDATA:
 *   HashLen (1 octet)  <-- THIS FUNCTION WRITES THIS LENGTH BYTE
 *   Hash    (HashLen octets)
 *
 * Caller contract (per your request):
 *   - Caller already handled zone_parse_space() around this field.
 *   - Therefore this function:
 *       * does NOT take `unsigned *depth`
 *       * does NOT call zone_parse_space()
 *       * does NOT treat whitespace specially
 *   - It decodes until the first character that is NOT a Base32hex character.
 *     (i.e., end-of-token is “first non-base32hex”.)
 *
 * Error handling:
 *   - If cursor > max: return max+1
 *   - Invalid / malformed encoding sets out->err_code=1 and out->err_cursor once,
 *     but we still emit a length byte and whatever bytes were decoded so far.
 *
 * "Accumulate errors" approach:
 *   - The decode table sets bit 0x80 for invalid characters.
 *   - We OR together decoded values to detect if anything invalid was used.
 *   - Leftover non-zero bits after decoding are treated as an error.
 *
 * Assumed external helpers (declared in zone-parse.h / zone-atom.h):
 *   - void wire_append_uint8(struct wire_record_t *out, uint8_t v, int *err);
 *   - void wire_append_bytes(struct wire_record_t *out, const void *p, size_t n, int *err);
 */

#include "zone-parse.h"
#include "zone-atom.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* -------------------------------------------------------------------------- */
/* helpers                                                                    */
/* -------------------------------------------------------------------------- */

/* -------------------------------------------------------------------------- */
/* Base32hex decode table (RFC 4648)                                          */
/* -------------------------------------------------------------------------- */
/*
 * Base32hex alphabet:
 *   0..9  A..V (case-insensitive)
 *
 * Table outputs:
 *   0..31  valid 5-bit values
 *   0x80   invalid (bit 0x80 indicates error)
 */
static const uint8_t b32hexdec[256] = {
#define XX 0x80
    /* 0x00..0x0F */
    XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,
    /* 0x10..0x1F */
    XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,
    /* 0x20..0x2F */
    XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,XX,
    /* 0x30..0x3F  '0'..'9' */
     0, 1, 2, 3, 4, 5, 6, 7, 8, 9, XX,XX,XX,XX,XX,XX,
    /* 0x40..0x4F  '@' 'A'..'O' => 10..24 */
    XX,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,
    /* 0x50..0x5F  'P'..'V' => 25..31 */
    25,26,27,28,29,30,31, XX,XX,XX,XX,XX,XX,XX,XX,XX,
    /* 0x60..0x6F  '`' 'a'..'o' => 10..24 */
    XX,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,
    /* 0x70..0x7F  'p'..'v' => 25..31 */
    25,26,27,28,29,30,31, XX,XX,XX,XX,XX,XX,XX,XX,XX,

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

/* A character is “base32hex” if its table entry is not invalid. */
static int
is_b32hex_char(unsigned char c)
{
    return (b32hexdec[c] & 0x80) == 0;
}

/* -------------------------------------------------------------------------- */
/* zone_atom_nsec3_hash                                                       */
/* -------------------------------------------------------------------------- */

size_t
zone_atom_nsec3_hash(const char *data, size_t cursor, size_t max,
                     struct wire_record_t *out)
{
    if (cursor > max)
        return max + 1;

    size_t start = cursor;

    /* Decode into bounded buffer (wire length byte is 0..255). */
    uint8_t decoded[255];
    size_t decoded_len = 0;

    /* Accumulate errors */
    uint8_t bad_or = 0;
    size_t first_bad = (size_t)(~(size_t)0);

    /* Bit accumulator: append 5 bits per char, pop 8 when ready. */
    uint32_t bitbuf = 0;
    unsigned bitcnt = 0;

    while (cursor < max) {
        unsigned char ch = (unsigned char)data[cursor];
        if (!is_b32hex_char(ch))
            break; /* end-of-token: first non-base32 character */

        uint8_t v = b32hexdec[ch];
        bad_or |= v;

        bitbuf = (bitbuf << 5) | (uint32_t)(v & 0x1f);
        bitcnt += 5;

        while (bitcnt >= 8) {
            uint8_t byte = (uint8_t)((bitbuf >> (bitcnt - 8)) & 0xFFu);
            bitcnt -= 8;

            if (decoded_len < sizeof(decoded)) {
                decoded[decoded_len++] = byte;
            } else {
                /* would overflow 255 bytes */
                bad_or |= 0x80;
                if (first_bad == (size_t)(~(size_t)0))
                    first_bad = cursor;
            }
        }

        cursor++;
    }

    /* Empty token is invalid (no base32 chars consumed) */
    if (cursor == start) {
        bad_or |= 0x80;
        if (first_bad == (size_t)(~(size_t)0))
            first_bad = start;
    }

    /* Leftover bits:
     * If leftover bits are non-zero, malformed encoding.
     * If leftover bits are present but zero, accept (common practice).
     */
    if (bitcnt != 0) {
        uint32_t leftover_mask = (1u << bitcnt) - 1u;
        if ((bitbuf & leftover_mask) != 0) {
            bad_or |= 0x80;
            if (first_bad == (size_t)(~(size_t)0))
                first_bad = cursor;
        }
    }

    /* Emit length byte + decoded bytes */
    {
        wire_append_uint8(out, (uint8_t)decoded_len);
        if (decoded_len)
            wire_append_bytes(out, decoded, decoded_len);
    }

    if (bad_or & 0x80) {
        if (first_bad == (size_t)(~(size_t)0))
            first_bad = start;
        return PARSE_ERR(1, first_bad, max, out);
    }

    return cursor;
}
