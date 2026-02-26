#ifndef ZONE_PARSE_TYPES_H
#define ZONE_PARSE_TYPES_H
#include <stddef.h>
#include <stdint.h>

struct wire_record_t;

/*
 * All TYPE-specific RDATA parsers.
 *
 * Common signature:
 *   data   - zonefile text buffer
 *   cursor - current offset into data
 *   max    - one-past-last valid offset
 *   out    - wire-format output record
 *   depth  - parenthesis nesting depth (for multiline records)
 *
 * Return value:
 *   New cursor position (or max+1 on hard bounds failure)
 */

/* Address records */
size_t zone_parse_A     (const char *data, size_t cursor, size_t max,
                         struct wire_record_t *out, unsigned *depth);
size_t zone_parse_AAAA  (const char *data, size_t cursor, size_t max,
                         struct wire_record_t *out, unsigned *depth);

/* Name-based records */
size_t zone_parse_CNAME (const char *data, size_t cursor, size_t max,
                         struct wire_record_t *out, unsigned *depth);
size_t zone_parse_NS    (const char *data, size_t cursor, size_t max,
                         struct wire_record_t *out, unsigned *depth);
size_t zone_parse_PTR   (const char *data, size_t cursor, size_t max,
                         struct wire_record_t *out, unsigned *depth);
size_t zone_parse_MX    (const char *data, size_t cursor, size_t max,
                         struct wire_record_t *out, unsigned *depth);

/* Textual records */
size_t zone_parse_TXT   (const char *data, size_t cursor, size_t max,
                         struct wire_record_t *out, unsigned *depth);
size_t zone_parse_SPF   (const char *data, size_t cursor, size_t max,
                         struct wire_record_t *out, unsigned *depth);

/* Certificate / crypto-related records */
size_t zone_parse_CAA   (const char *data, size_t cursor, size_t max,
                         struct wire_record_t *out, unsigned *depth);
size_t zone_parse_DS    (const char *data, size_t cursor, size_t max,
                         struct wire_record_t *out, unsigned *depth);
size_t zone_parse_TLSA  (const char *data, size_t cursor, size_t max,
                         struct wire_record_t *out, unsigned *depth);
size_t zone_parse_SSHFP (const char *data, size_t cursor, size_t max,
                         struct wire_record_t *out, unsigned *depth);

/* Service discovery / routing records */
size_t zone_parse_SRV   (const char *data, size_t cursor, size_t max,
                         struct wire_record_t *out, unsigned *depth);
size_t zone_parse_NAPTR (const char *data, size_t cursor, size_t max,
                         struct wire_record_t *out, unsigned *depth);

/* Authority / zone control */
size_t zone_parse_SOA   (const char *data, size_t cursor, size_t max,
                         struct wire_record_t *out, unsigned *depth);

/* SVCB-family records */
size_t zone_parse_SVCB  (const char *data, size_t cursor, size_t max,
                         struct wire_record_t *out, unsigned *depth);
size_t zone_parse_HTTPS (const char *data, size_t cursor, size_t max, struct wire_record_t *out, unsigned *depth);

size_t zone_parse_DNSKEY (const char *data, size_t cursor, size_t max, struct wire_record_t *out, unsigned *depth);
size_t zone_parse_RRSIG (const char *data, size_t cursor, size_t max, struct wire_record_t *out, unsigned *depth);
size_t zone_parse_NSEC(const char *data, size_t cursor, size_t max, struct wire_record_t *out, unsigned *depth);
size_t zone_parse_NSEC3(const char *data, size_t cursor, size_t max, struct wire_record_t *out, unsigned *depth);
size_t zone_parse_IPSECKEY(const char *data, size_t cursor, size_t max, struct wire_record_t *out, unsigned *depth);

size_t zone_parse_ZONEMD(const char *data, size_t cursor, size_t max, struct wire_record_t *out, unsigned *depth);
size_t zone_parse_URI(const char *data, size_t cursor, size_t max, struct wire_record_t *out, unsigned *depth);
size_t zone_parse_SMIMEA(const char *data, size_t cursor, size_t max, struct wire_record_t *out, unsigned *depth);
size_t zone_parse_DNAME(const char *data, size_t cursor, size_t max, struct wire_record_t *out, unsigned *depth);
size_t zone_parse_GENERIC(const char *data, size_t cursor, size_t max, struct wire_record_t *out, unsigned *depth);


#endif
