/*
 This is the list of records supported by Amazon's Route 53 and Google Cloud:
 
 A AAAA CAA CNAME DS HTTPS MX NAPTR NS PTR SOA SPF SRV SSHFP SVCB TLSA TXT
 
 https://docs.cloud.google.com/dns/docs/records-overview
 https://digitalcloud.training/amazon-route-53/
 
 */
#include "zone-parse.h"
#include "zone-parse-types.h"
#include "zone-parse-mask.h"
#include "zone-parse-record.h"
#include "zone-error.h"
#include "zone-atom.h"
#include <assert.h>




/* RDATA parsers (MX-style): call atom parser, parse space between atoms, finish at end.
 *
 * Notes:
 *  - I’m using the simplest generic atom names: int8/int16/int32, name, ipv4/ipv6,
 *    txt (character-string), and hex (contiguous hex/base16 blob).
 *  - For “lists” (TXT/SPF strings; SVCB/HTTPS params), I’m using a single atom that
 *    consumes one-or-more tokens of that kind: zone_atom_txt_list(), zone_atom_svcparams().
 */

size_t
zone_parse_A(const char *data, size_t cursor, size_t max,
             struct wire_record_t *out, unsigned *depth)
{

    /* typical: 192.0.2.1 */
    cursor = zone_atom_ipv4(data, cursor, max, out);
    cursor = zone_parse_space(data, cursor, max, out, depth);

    
    return cursor;
}

size_t
zone_parse_AAAA(const char *data, size_t cursor, size_t max,
                struct wire_record_t *out, unsigned *depth)
{

    /* typical: 2001:db8::1 */
    cursor = zone_atom_ipv6(data, cursor, max, out);
    cursor = zone_parse_space(data, cursor, max, out, depth);

    
    return cursor;
}

size_t
zone_parse_CAA(const char *data, size_t cursor, size_t max,
               struct wire_record_t *out, unsigned *depth)
{

    /* typical: 0 */
    cursor = zone_atom_int8(data, cursor, max, out);   /* flags */
    cursor = zone_parse_space(data, cursor, max, out, depth);

    /* typical: issue | issuewild | iodef */
    cursor = zone_atom_txt(data, cursor, max, out);    /* tag (ASCII token/char-string) */
    cursor = zone_parse_space(data, cursor, max, out, depth);

    /* typical: "letsencrypt.org" | "mailto:hostmaster@example.com" */
    cursor = zone_atom_caaval(data, cursor, max, out);    /* value (quoted/char-string) */
    cursor = zone_parse_space(data, cursor, max, out, depth);

    
    return cursor;
}

size_t
zone_parse_CNAME(const char *data, size_t cursor, size_t max,
                 struct wire_record_t *out, unsigned *depth)
{
    /* typical: target.example.com. */
    cursor = zone_atom_name(data, cursor, max, out);
    cursor = zone_parse_space(data, cursor, max, out, depth);

    return cursor;
}

size_t
zone_parse_DS(const char *data, size_t cursor, size_t max,
              struct wire_record_t *out, unsigned *depth)
{


    /* typical: 60485 */
    cursor = zone_atom_int16(data, cursor, max, out);  /* key tag */
    cursor = zone_parse_space(data, cursor, max, out, depth);

    /* typical: 8 (RSASHA256), 13 (ECDSAP256SHA256), 15 (ED25519) */
    cursor = zone_atom_int8(data, cursor, max, out);   /* algorithm */
    cursor = zone_parse_space(data, cursor, max, out, depth);

    /* typical: 2 (SHA-256), 4 (SHA-384) */
    cursor = zone_atom_int8(data, cursor, max, out);   /* digest type */
    cursor = zone_parse_space(data, cursor, max, out, depth);

    /* typical: 3D2D... (hex) */
    cursor = zone_atom_hexes(data, cursor, max, out, depth);    /* digest */
    cursor = zone_parse_space(data, cursor, max, out, depth);

    //printf("%.*s\n", (unsigned)(cursor - start), data + start);
    
    return cursor;
}

size_t
zone_parse_HTTPS(const char *data, size_t cursor, size_t max,
                 struct wire_record_t *out, unsigned *depth)
{
    /* typical: 1 */
    cursor = zone_atom_int16(data, cursor, max, out);  /* priority */
    cursor = zone_parse_space(data, cursor, max, out, depth);

    /* typical: . | svc.example.com. */
    cursor = zone_atom_name(data, cursor, max, out);   /* target name */
    cursor = zone_parse_space(data, cursor, max, out, depth);

    /* typical: alpn="h2,h3" port=443 ipv4hint=192.0.2.1 */
    cursor = zone_atom_svcparams(data, cursor, max, out, depth); /* key=val list (consumes remainder) */
    cursor = zone_parse_space(data, cursor, max, out, depth);

    return cursor;
}

size_t
zone_parse_MX(const char *data, size_t cursor, size_t max,
              struct wire_record_t *out, unsigned *depth)
{


    /* typical: 10 */
    cursor = zone_atom_int16(data, cursor, max, out);  /* preference */
    cursor = zone_parse_space(data, cursor, max, out, depth);

    /* typical: mail.example.com. */
    cursor = zone_atom_name(data, cursor, max, out);   /* exchange */
    cursor = zone_parse_space(data, cursor, max, out, depth);

    
    return cursor;
}

size_t
zone_parse_NAPTR(const char *data, size_t cursor, size_t max,
                 struct wire_record_t *out, unsigned *depth)
{

    /* typical: 100 */
    cursor = zone_atom_int16(data, cursor, max, out);  /* order */
    cursor = zone_parse_space(data, cursor, max, out, depth);

    /* typical: 10 */
    cursor = zone_atom_int16(data, cursor, max, out);  /* preference */
    cursor = zone_parse_space(data, cursor, max, out, depth);

    /* typical: "U" | "S" | "A" | "" */
    cursor = zone_atom_txt(data, cursor, max, out);    /* flags */
    cursor = zone_parse_space(data, cursor, max, out, depth);

    /* typical: "E2U+sip" */
    cursor = zone_atom_txt(data, cursor, max, out);    /* services */
    cursor = zone_parse_space(data, cursor, max, out, depth);

    /* typical: "!^.*$!sip:info@example.com!" | "" */
    cursor = zone_atom_txt(data, cursor, max, out);    /* regexp */
    cursor = zone_parse_space(data, cursor, max, out, depth);

    /* typical: . | replacement.example.com. */
    cursor = zone_atom_name(data, cursor, max, out);   /* replacement */
    cursor = zone_parse_space(data, cursor, max, out, depth);

    
    return cursor;
}

size_t
zone_parse_NS(const char *data, size_t cursor, size_t max,
              struct wire_record_t *out, unsigned *depth)
{
    /* typical: ns1.example.net. */
    cursor = zone_atom_name(data, cursor, max, out);
    cursor = zone_parse_space(data, cursor, max, out, depth);

    
    return cursor;
}

size_t
zone_parse_PTR(const char *data, size_t cursor, size_t max,
               struct wire_record_t *out, unsigned *depth) {

    /* typical: host.example.com. */
    cursor = zone_atom_name(data, cursor, max, out);
    cursor = zone_parse_space(data, cursor, max, out, depth);

    
    return cursor;
}

size_t
zone_parse_SOA(const char *data, size_t cursor, size_t max,
               struct wire_record_t *out, unsigned *depth)
{


    /* typical: ns1.example.com. */
    cursor = zone_atom_name(data, cursor, max, out);   /* mname */
    cursor = zone_parse_space(data, cursor, max, out, depth);

    /* typical: hostmaster.example.com. */
    cursor = zone_atom_name(data, cursor, max, out);   /* rname */
    cursor = zone_parse_space(data, cursor, max, out, depth);

    /* typical: 2026020601 */
    cursor = zone_atom_int32(data, cursor, max, out);  /* serial */
    cursor = zone_parse_space(data, cursor, max, out, depth);

    /* typical: 3600 */
    cursor = zone_atom_int32(data, cursor, max, out);  /* refresh */
    cursor = zone_parse_space(data, cursor, max, out, depth);

    /* typical: 600 */
    cursor = zone_atom_int32(data, cursor, max, out);  /* retry */
    cursor = zone_parse_space(data, cursor, max, out, depth);

    /* typical: 1209600 */
    cursor = zone_atom_int32(data, cursor, max, out);  /* expire */
    cursor = zone_parse_space(data, cursor, max, out, depth);

    /* typical: 300 */
    cursor = zone_atom_int32(data, cursor, max, out);  /* minimum */
    cursor = zone_parse_space(data, cursor, max, out, depth);

    
    return cursor;
}

size_t
zone_parse_SPF(const char *data, size_t cursor, size_t max,
               struct wire_record_t *out, unsigned *depth)
{


    /* typical: "v=spf1 ip4:192.0.2.0/24 -all" (possibly split across multiple quoted chunks) */
    cursor = zone_atom_txt_list(data, cursor, max, out, depth); /* one-or-more character-strings */
    cursor = zone_parse_space(data, cursor, max, out, depth);

    
    return cursor;
}

size_t
zone_parse_SRV(const char *data, size_t cursor, size_t max,
               struct wire_record_t *out, unsigned *depth)
{

    /* typical: 10 */
    cursor = zone_atom_int16(data, cursor, max, out);  /* priority */
    cursor = zone_parse_space(data, cursor, max, out, depth);

    /* typical: 5 */
    cursor = zone_atom_int16(data, cursor, max, out);  /* weight */
    cursor = zone_parse_space(data, cursor, max, out, depth);

    /* typical: 443 */
    cursor = zone_atom_int16(data, cursor, max, out);  /* port */
    cursor = zone_parse_space(data, cursor, max, out, depth);

    /* typical: target.example.com. */
    cursor = zone_atom_name(data, cursor, max, out);   /* target */
    cursor = zone_parse_space(data, cursor, max, out, depth);

    
    return cursor;
}

size_t
zone_parse_SSHFP(const char *data, size_t cursor, size_t max,
                 struct wire_record_t *out, unsigned *depth)
{


    /* typical: 1 (RSA), 2 (DSA), 3 (ECDSA), 4 (ED25519) */
    cursor = zone_atom_int8(data, cursor, max, out);   /* algorithm */
    cursor = zone_parse_space(data, cursor, max, out, depth);

    /* typical: 1 (SHA-1), 2 (SHA-256) */
    cursor = zone_atom_int8(data, cursor, max, out);   /* fingerprint type */
    cursor = zone_parse_space(data, cursor, max, out, depth);

    /* typical: 1234ABCD... (hex) */
    cursor = zone_atom_hex_c(data, cursor, max, out);    /* fingerprint */
    cursor = zone_parse_space(data, cursor, max, out, depth);

    
    return cursor;
}

size_t
zone_parse_SVCB(const char *data, size_t cursor, size_t max,
                struct wire_record_t *out, unsigned *depth)
{

    /* typical: 1 */
    cursor = zone_atom_int16(data, cursor, max, out);  /* priority */
    cursor = zone_parse_space(data, cursor, max, out, depth);

    /* typical: . | svc.example.com. */
    cursor = zone_atom_name(data, cursor, max, out);   /* target name */
    cursor = zone_parse_space(data, cursor, max, out, depth);

    /* typical: alpn="h2" port=8443 ipv6hint=2001:db8::1 */
    cursor = zone_atom_svcparams(data, cursor, max, out, depth); /* key=val list (consumes remainder) */
    cursor = zone_parse_space(data, cursor, max, out, depth);

    
    return cursor;
}

size_t
zone_parse_TLSA(const char *data, size_t cursor, size_t max,
                struct wire_record_t *out, unsigned *depth)
{

    /* typical: 3 */
    cursor = zone_atom_int8(data, cursor, max, out);   /* usage */
    cursor = zone_parse_space(data, cursor, max, out, depth);

    /* typical: 1 */
    cursor = zone_atom_int8(data, cursor, max, out);   /* selector */
    cursor = zone_parse_space(data, cursor, max, out, depth);

    /* typical: 1 (SHA-256), 2 (SHA-512) */
    cursor = zone_atom_int8(data, cursor, max, out);   /* matching type */
    cursor = zone_parse_space(data, cursor, max, out, depth);

    /* typical: 5A5B... (hex) */
    cursor = zone_atom_hex_c(data, cursor, max, out);    /* certificate association data */
    cursor = zone_parse_space(data, cursor, max, out, depth);

    
    return cursor;
}

size_t
zone_parse_TXT(const char *data, size_t cursor, size_t max,
               struct wire_record_t *out, unsigned *depth)
{

    /* typical: "hello" "world" (one or more quoted chunks) */
    cursor = zone_atom_txt_list(data, cursor, max, out, depth); /* one-or-more character-strings */
    cursor = zone_parse_space(data, cursor, max, out, depth);

    
    return cursor;
}
