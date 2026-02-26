/*
  These are DNSSEC and other emerging keys
 DNSKEY RRSIG NSEC NSEC3 IPSECKEY ZONEMD URI SMIMEA DNAME
 */
/* zone-parse-types2.c
 *
 * Parse additional RR TYPE RDATA formats:
 *   DNSKEY, RRSIG, NSEC, NSEC3, IPSECKEY, ZONEMD, URI, SMIMEA, DNAME
 *
 * Pattern:
 *   - Call an atom parser
 *   - Parse space between fields
 *
 * Assumptions:
 *   - Everything is declared in "zone-parse.h" and "zone-atom.h"
 *   - Atom parsers exist elsewhere with appropriately named functions.
 *   - Atom parsers that must consume/interpret whitespace/comments/parentheses take `unsigned *depth`
 *     (notably: base64/hexes style remainder fields, type bitmaps, etc.).
 */

#include "zone-parse.h"
#include "zone-atom.h"
#include "zone-parse-types.h"

static inline int is_digit(char c) {
    return (c >= (unsigned char)'0' && c <= (unsigned char)'9');
}

size_t
parse_int(const char *data, size_t cursor, size_t max,
            unsigned *value, struct wire_record_t *out) {
    uint64_t number = 0;
    
    if (cursor > max)
        return max + 1;
    for (;;) {
        char c = data[cursor];
        if (is_digit(c)) {
            number *= 10;
            number += c - '0';
            cursor++;
        } else
            break;
    }
    if (number > 0xFFFF)
        return PARSE_ERR(ZONE_ERROR_EXPECTED_GENERIC, cursor, max, out);

    *value = (unsigned)number;
    return cursor;
}

size_t
zone_parse_GENERIC(const char *data, size_t cursor, size_t max,
                  struct wire_record_t *out, unsigned *depth) {
    unsigned length = 0;
    
    /*
     * RFC 3597 - starts with `\#` to indicate generic/unknown encoding
     */
    if (data[cursor] != '\\' && data[cursor+1] != '#') {
        return PARSE_ERR(ZONE_ERROR_EXPECTED_GENERIC, cursor, max, out);
    } else
        cursor += 2;
    cursor = zone_parse_space(data, cursor, max, out, depth);
    
    /*
     * Get a count of the number of bytes, which is redundant,
     */
    cursor = parse_int(data, cursor, max, &length, out);
    cursor = zone_parse_space(data, cursor, max, out, depth);

    /*
     * Get the hex encoding of the wire rrdata format.
     */
    cursor = zone_atom_hexes(data, cursor, max, out, depth);
    cursor = zone_parse_space(data, cursor, max, out, depth);

    
    return cursor;
}

size_t
zone_parse_DNSKEY(const char *data, size_t cursor, size_t max,
                  struct wire_record_t *out, unsigned *depth)
{
    if (data[cursor] == '\\' && data[cursor+1] == '#') {
        return zone_parse_GENERIC(data, cursor, max, out, depth);
    }

    /* typical: 257 (KSK) */
    cursor = zone_atom_int16(data, cursor, max, out);      /* flags */
    cursor = zone_parse_space(data, cursor, max, out, depth);

    /* typical: 3 (DNSSEC) */
    cursor = zone_atom_int8(data, cursor, max, out);       /* protocol */
    cursor = zone_parse_space(data, cursor, max, out, depth);

    /* typical: 8 (RSASHA256), 13 (ECDSAP256SHA256), 15 (ED25519) */
    cursor = zone_atom_int8(data, cursor, max, out);       /* algorithm */
    cursor = zone_parse_space(data, cursor, max, out, depth);

    /* typical: AwEAAc... (base64, often split with whitespace/parentheses) */
    cursor = zone_atom_base64a(data, cursor, max, out, depth); /* public key (remainder) */
    cursor = zone_parse_space(data, cursor, max, out, depth);

    
    return cursor;
}

size_t
zone_parse_RRSIG(const char *data, size_t cursor, size_t max,
                 struct wire_record_t *out, unsigned *depth)
{
    if (data[cursor] == '\\' && data[cursor+1] == '#') {
        return zone_parse_GENERIC(data, cursor, max, out, depth);
    }

    /* typical: A, AAAA, MX, SOA, ... (type covered) */
    cursor = zone_atom_type(data, cursor, max, out);       /* type covered (u16 in wire) */
    cursor = zone_parse_space(data, cursor, max, out, depth);

    /* typical: 13 */
    cursor = zone_atom_int8(data, cursor, max, out);       /* algorithm */
    cursor = zone_parse_space(data, cursor, max, out, depth);

    /* typical: 2 */
    cursor = zone_atom_int8(data, cursor, max, out);       /* labels */
    cursor = zone_parse_space(data, cursor, max, out, depth);

    /* typical: 3600 */
    cursor = zone_atom_int32(data, cursor, max, out);      /* original TTL */
    cursor = zone_parse_space(data, cursor, max, out, depth);

    /* typical: 20260206120000 (YYYYMMDDHHMMSS) */
    cursor = zone_atom_expire2(data, cursor, max, out);     /* signature expiration (u32 in wire) */
    cursor = zone_parse_space(data, cursor, max, out, depth);

    /* typical: 20260106120000 (YYYYMMDDHHMMSS) */
    cursor = zone_atom_expire2(data, cursor, max, out);     /* signature inception (u32 in wire) */
    cursor = zone_parse_space(data, cursor, max, out, depth);

    /* typical: 60485 */
    cursor = zone_atom_int16(data, cursor, max, out);      /* key tag */
    cursor = zone_parse_space(data, cursor, max, out, depth);

    /* typical: signer.example.com. */
    cursor = zone_atom_name(data, cursor, max, out);       /* signer name */
    cursor = zone_parse_space(data, cursor, max, out, depth);

    /* typical: base64 signature, often split */
    cursor = zone_atom_base64c(data, cursor, max, out, depth); /* signature (remainder) */
    cursor = zone_parse_space(data, cursor, max, out, depth);

    
    return cursor;
}

size_t
zone_parse_NSEC(const char *data, size_t cursor, size_t max,
                struct wire_record_t *out, unsigned *depth) {
    if (data[cursor] == '\\' && data[cursor+1] == '#') {
        return zone_parse_GENERIC(data, cursor, max, out, depth);
    }

    /* typical: next.example.com. */
    cursor = zone_atom_name(data, cursor, max, out);       /* next domain name */
    cursor = zone_parse_space(data, cursor, max, out, depth);

    /* typical: A NS SOA MX RRSIG NSEC DNSKEY (type bitmap, may wrap lines) */
    cursor = zone_atom_bitmap(data, cursor, max, out, depth); /* remainder */
    cursor = zone_parse_space(data, cursor, max, out, depth);

    
    return cursor;
}

/*
 
 1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Hash Alg.   |     Flags     |          Iterations           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Salt Length  |                     Salt                      /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Hash Length  |             Next Hashed Owner Name            /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/                         Type Bit Maps                         /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


 */
size_t
zone_parse_NSEC3(const char *data, size_t cursor, size_t max,
                 struct wire_record_t *out, unsigned *depth)
{
    if (data[cursor] == '\\' && data[cursor+1] == '#') {
        return zone_parse_GENERIC(data, cursor, max, out, depth);
    }

    /* typical: 1 */
    cursor = zone_atom_int8(data, cursor, max, out);       /* hash algorithm */
    cursor = zone_parse_space(data, cursor, max, out, depth);

    /* typical: 0 or 1 */
    cursor = zone_atom_int8(data, cursor, max, out);       /* flags */
    cursor = zone_parse_space(data, cursor, max, out, depth);

    /* typical: 10 */
    cursor = zone_atom_int16(data, cursor, max, out);      /* iterations */
    cursor = zone_parse_space(data, cursor, max, out, depth);

    /* typical: -  (or base16/base32-ish salt depending on your atom policy) */
    if (data[cursor] == '-') {
        cursor++;
        wire_append_uint8(out, 0);
    } else {
        cursor = zone_atom_hex_l(data, cursor, max, out);       /* salt bytes (supports '-') */
    }
    cursor = zone_parse_space(data, cursor, max, out, depth);

    /* typical: 2VPTU5TIMAMQ0GJ... (next hashed owner name, base32hex) */
    cursor = zone_atom_nsec3_hash(data, cursor, max, out); /* next hashed name */
    cursor = zone_parse_space(data, cursor, max, out, depth);

    /* typical: A NS SOA MX RRSIG NSEC3PARAM (type bitmap, may wrap) */
    cursor = zone_atom_bitmap(data, cursor, max, out, depth); /* remainder */
    cursor = zone_parse_space(data, cursor, max, out, depth);

    
    return cursor;
}

size_t
zone_parse_IPSECKEY(const char *data, size_t cursor, size_t max,
                    struct wire_record_t *out, unsigned *depth)
{
    if (data[cursor] == '\\' && data[cursor+1] == '#') {
        return zone_parse_GENERIC(data, cursor, max, out, depth);
    }

    unsigned gwtype = 0;
    
    /* typical: 10 */
    cursor = zone_atom_int8(data, cursor, max, out);       /* precedence */
    cursor = zone_parse_space(data, cursor, max, out, depth);

    /* typical: 0 (none), 1 (IPv4), 2 (IPv6), 3 (domain name) */
    cursor = zone_atom_int8x(data, cursor, max, out, &gwtype);       /* gateway type */
    cursor = zone_parse_space(data, cursor, max, out, depth);

    /* typical: 0 (no key), 1 (DSS), 2 (RSA), ... */
    cursor = zone_atom_int8(data, cursor, max, out);       /* algorithm */
    cursor = zone_parse_space(data, cursor, max, out, depth);

    /* typical: . | 192.0.2.1 | 2001:db8::1 | gw.example.com. */
    /* Type 1/2/3 parse their respective atoms. Those atoms typically stop on
      * non-token characters by themselves; we still pass through zone_parse_space().
      */
    switch (gwtype) {
    case 1:
        /* typical: 192.0.2.1 */
        cursor = zone_atom_ipv4(data, cursor, max, out);
        break;
    case 2:
        /* typical: 2001:db8::1 */
        cursor = zone_atom_ipv6(data, cursor, max, out);
        break;
    case 3:
        /* typical: gw.example.com. */
        cursor = zone_atom_name(data, cursor, max, out);
        break;
    default:
        /* error TODO: error */
        break;
    }
    cursor = zone_parse_space(data, cursor, max, out, depth);

    /* typical: base64 key material, may wrap */
    if (data[cursor] == '-') {
        cursor++;
    } else {
        cursor = zone_atom_base64a(data, cursor, max, out, depth);  /* public key (remainder) */
    }
    cursor = zone_parse_space(data, cursor, max, out, depth);

    
    return cursor;
}

size_t
zone_parse_ZONEMD(const char *data, size_t cursor, size_t max,
                  struct wire_record_t *out, unsigned *depth)
{
    if (data[cursor] == '\\' && data[cursor+1] == '#') {
        return zone_parse_GENERIC(data, cursor, max, out, depth);
    }
    
    /* typical: 2026020601 */
    cursor = zone_atom_int32(data, cursor, max, out);      /* serial */
    cursor = zone_parse_space(data, cursor, max, out, depth);

    /* typical: 1 */
    cursor = zone_atom_int8(data, cursor, max, out);       /* scheme */
    cursor = zone_parse_space(data, cursor, max, out, depth);

    /* typical: 1 (SHA-384), 2 (SHA-512) */
    cursor = zone_atom_int8(data, cursor, max, out);       /* hash algorithm */
    cursor = zone_parse_space(data, cursor, max, out, depth);

    /* typical: hex digest (may be split with whitespace) */
    cursor = zone_atom_hexes(data, cursor, max, out, depth); /* digest (remainder-ish) */
    cursor = zone_parse_space(data, cursor, max, out, depth);

    
    return cursor;
}

size_t
zone_parse_URI(const char *data, size_t cursor, size_t max,
               struct wire_record_t *out, unsigned *depth)
{
    if (data[cursor] == '\\' && data[cursor+1] == '#') {
        return zone_parse_GENERIC(data, cursor, max, out, depth);
    }

    /* typical: 10 */
    cursor = zone_atom_int16(data, cursor, max, out);      /* priority */
    cursor = zone_parse_space(data, cursor, max, out, depth);

    /* typical: 1 */
    cursor = zone_atom_int16(data, cursor, max, out);      /* weight */
    cursor = zone_parse_space(data, cursor, max, out, depth);

    /* typical: "https://example.com/service" */
    cursor = zone_atom_txt(data, cursor, max, out); /* target (stringish; may need quotes/escapes) */
    cursor = zone_parse_space(data, cursor, max, out, depth);

    
    return cursor;
}

size_t
zone_parse_SMIMEA(const char *data, size_t cursor, size_t max,
                  struct wire_record_t *out, unsigned *depth)
{
    if (data[cursor] == '\\' && data[cursor+1] == '#') {
        return zone_parse_GENERIC(data, cursor, max, out, depth);
    }

    /* typical: 3 */
    cursor = zone_atom_int8(data, cursor, max, out);       /* usage */
    cursor = zone_parse_space(data, cursor, max, out, depth);

    /* typical: 1 */
    cursor = zone_atom_int8(data, cursor, max, out);       /* selector */
    cursor = zone_parse_space(data, cursor, max, out, depth);

    /* typical: 1 (SHA-256), 2 (SHA-512) */
    cursor = zone_atom_int8(data, cursor, max, out);       /* matching type */
    cursor = zone_parse_space(data, cursor, max, out, depth);

    /* typical: hex cert association data (may be split) */
    cursor = zone_atom_hexes(data, cursor, max, out, depth);
    cursor = zone_parse_space(data, cursor, max, out, depth);

    
    return cursor;
}

size_t
zone_parse_DNAME(const char *data, size_t cursor, size_t max,
                 struct wire_record_t *out, unsigned *depth)
{
    if (data[cursor] == '\\' && data[cursor+1] == '#') {
        return zone_parse_GENERIC(data, cursor, max, out, depth);
    }

    /* typical: target.example.com. */
    cursor = zone_atom_name(data, cursor, max, out);       /* target */
    cursor = zone_parse_space(data, cursor, max, out, depth);

    
    return cursor;
}
