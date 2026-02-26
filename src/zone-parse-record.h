/* zone-parse-record.h
 *
 * Purpose
 * -------
 * Glue code that turns a pre-scanned DNS zonefile record (owner name + remainder
 * of record text) into a single DNS “wire format” byte chunk.
 *
 * Inputs
 * ------
 * dns_record_t (from zone-scan.h):
 *   - name/name_len: owner name text (already separated by a prior scan step)
 *   - data/data_len/data_offset: remainder of record text to parse (TTL/CLASS/TYPE/RDATA)
 *
 * Outputs
 * -------
 * wire_record_t (from zone-parse.h):
 *   - wire: caller-allocated buffer (expected >= 64k; we still bounds-check)
 *   - name_length: length of the encoded owner name in wire[]
 *   - buf_length: total length of the encoded record chunk in wire[]
 *   - error_code/error_cursor: set on any parse/overflow error
 *
 * Pipeline
 * --------
 * 1) Encode the owner name into DNS wire format:
 *      zone_atom_name4(name_text, 0, name_len, out->wire, &status)
 *
 * 2) Parse the record header fields from data (TTL/CLASS/TYPE, etc):
 *      zone_parse_header(data, data_offset, data_len, &status, &depth)
 *
 * 3) Resolve rrtype parser by rrtype_idx:
 *      zone_type_by_index(status.rrtype_idx)
 *
 * 4) Parse RDATA using the resolved type parser:
 *      type->parse(data, cursor, data_len, &status)
 *
 * Error Handling
 * --------------
 * We treat any non-zero status.err_code as failure. We also treat any cursor
 * return that exceeds max as failure. We also bounds-check status.wire_len
 * against out->wire.max.
 *
 * Notes
 * -----
 * - All parsing/encoding primitives and the zone_status_t definition live in
 *   zone-parse.h, per the larger project structure.
 * - This module only sequences calls, copies resulting lengths into wire_record_t,
 *   and propagates errors/offsets.
 */

#ifndef ZONE_PARSE_RECORD_H
#define ZONE_PARSE_RECORD_H

#include <stddef.h>

#include "zone-scan.h"  /* dns_record_t */
#include "zone-parse.h" /* wire_record_t, zone_status_t, zone_atom_name4, zone_parse_header, zone_type_by_index */

#ifdef __cplusplus
extern "C" {
#endif


typedef struct zone_state_t {
    const unsigned char *prior_name;
    size_t prior_name_length;
    unsigned char origin[256];
    size_t origin_length;
    unsigned ttl;
    size_t line_number;
    size_t line_offset;
} zone_state_t;

struct wire_record_t;
struct zone_state_t;

size_t zone_parse_record(const char *data, size_t cursor, size_t max,
                         struct zone_state_t *state,
                         struct wire_record_t *out);


size_t
zone_parse_space(const char *data, size_t cursor, size_t max,
                  struct wire_record_t *out,
                  unsigned *depth);
#ifdef __cplusplus
}
#endif

#endif /* ZONE_PARSE_RECORD_H */

