#include "zone-slow-header.h"
#include "zone-parse.h"
#include "zone-atom.h" /* zone_parse_space() */



/* ------------------------------ helpers ----------------------------------- */
static inline int is_digit(char c) {
    return (c >= (unsigned char)'0' && c <= (unsigned char)'9');
}
static inline int is_alnum_ascii(char c) {
    if (c >= (unsigned char)'0' && c <= (unsigned char)'9') return 1;
    if (c >= (unsigned char)'A' && c <= (unsigned char)'Z') return 1;
    if (c >= (unsigned char)'a' && c <= (unsigned char)'z') return 1;
    return 0;
}


static inline size_t
my_parse_ownername(const char *data, size_t cursor, size_t max,
                wire_record_t *out) {
    size_t next;
    size_t orig_wire_len = out->wire.len;

    /*
     * 1. A name consisting of just an `@` symbol refers to
     * an empty prefix to which the $ORIGIN suffix will be
     * added.
     */
    if (data[cursor] == '@') {
        next = cursor + 1;
        out->is_fqdn = 0;
        goto append_origin;
    }
    
    /*
     * 2. Grab the name from the input.
     */
    next = zone_atom_name_slow(data, cursor, max, out);
    
    /*
     * 3. If not fully-qualified (FQDN), then append
     * the $ORIGIN.
     */
append_origin:
    if (!out->is_fqdn) {
        /* if not fully qualified it, append the origin */
        wire_append_bytes(out, out->state.origin, out->state.origin_length);
    }
    out->ownername_length = out->wire.len - orig_wire_len;
    
    return next; //zone_mask_skip_nospace1(data, cursor, max, next - cursor);
}
size_t
zone_slow_header(const char *data, size_t cursor, size_t max,
                  struct wire_record_t *out,
                  unsigned *depth)
{
    int err = 0;
    unsigned rrttl = out->state.default_ttl;
    unsigned rrclass = 1;

    cursor = my_parse_ownername(data, cursor, max, out);
    
    if (is_zone_space(data[cursor]))
        cursor = zone_slow_space(data, cursor, max, out, depth);

    /*
     * Parse up to three fields until we find a TYPE
     */
    for (int field = 0; field < 3; field++) {
        
        if (cursor >= max)
            goto fail;
        
        
        /* ---- TTL ---- */
        if (field == 0 && is_digit(data[cursor])) {
            cursor = parse_ttl_seconds(data, cursor, max, &rrttl, &err);
            cursor = zone_slow_space(data, cursor, max, out, depth);
            continue;
        }
        
        /* ---- CLASS/TYPE ---- */
        size_t next = cursor;
        while (is_alnum_ascii(data[next]))
            next++;
        unsigned type_value;
        unsigned type_idx;
        if (next - cursor == 2 && data[cursor+0] == 'I' && data[cursor+1] == 'N') {
            type_idx = 1;
            type_value = 1;
        } else {
            type_idx = zone_type2_lookup(data+cursor, next - cursor, &type_value);
            if (type_idx == 0)
                goto fail;
        }
        cursor = next;

        /* See if it's a `class` rather than a `type` */
        if (type_idx < 4) {
            rrclass = type_value;
            cursor = zone_slow_space(data, cursor, max, out, depth);
            continue;
        }
        
        /* ---- TYPE ---- */
        out->rrtype.idx = type_idx;
        out->rrtype.value = type_value;
        
        wire_append_uint16(out, out->rrtype.value);
        wire_append_uint16(out, rrclass);
        wire_append_uint32(out, rrttl);
        
        /*
         * Now that we've found the TYPE, strip as much
         * whitespace as we can.
         */
        cursor = zone_slow_space(data, cursor, max, out, depth);
        return cursor;
    }

    /*
     * If we processed 3 fields without finding TYPE => error => fallback
     */
fail:
    return PARSE_ERR(err, cursor, max, out);
}

