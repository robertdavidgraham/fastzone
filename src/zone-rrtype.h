#ifndef ZONE_RRTYPE_H
#define ZONE_RRTYPE_H
#include <stddef.h>
#include <stdint.h>
//
//  rrtype.h
//  fastzone
//
//  Created by Martin Woodford on 1/20/26.
//


// Up to 10 parser functions, as requested.
#ifndef ZONE_RRTYPE_PARSER_MAX
#define ZONE_RRTYPE_PARSER_MAX 10
#endif

typedef int (*rrdata_format_fn)(char *dst, size_t dst_len,
                                const uint8_t *rdata, size_t rdata_len);

typedef int (*rrdata_parse_fn)(const char *s, size_t s_len,
                               uint8_t *out_rdata, size_t *inout_rdata_len);

struct rrtype_t {
  uint16_t          value;
  const char       *name_caps;   // NUL-terminated ALL-CAPS mnemonic, or 0
  rrdata_format_fn  format;      // wire->zone text formatter
  rrdata_parse_fn   parsers[ZONE_RRTYPE_PARSER_MAX]; // zone text->wire parsers
};

// Return codes:
//  0  found / produced rrtype
// -1  not found (non-TYPEnnnn unknown mnemonic)
// -2  invalid input / malformed TYPE#### / out==NULL
int zone_rrtype_lookup(const char *s, size_t s_len, const struct rrtype_t **out);

#endif
