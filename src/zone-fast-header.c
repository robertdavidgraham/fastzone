#include "zone-fast-header.h"
#include "zone-slow-header.h"
#include "zone-parse.h"
#include "util-simd.h"
#include "zone-fast-classify.h"


static int is_digit(char c) {
    return ('0' <= c && c <= '9');
}

/* ------------ wire write helpers (big-endian) ------------ */
static inline void store_be16(uint8_t *p, unsigned v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v >> 0);
}
static inline void store_be32(uint8_t *p, unsigned v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)(v >> 0);
}



size_t
zone_fast_header(const char *data, size_t cursor, size_t max,
                   struct wire_record_t *out,
                   unsigned *depth)
{
    /* This is the "classification tape" */
    tokentape_t *whitespace = out->whitespace;
    tokentape_t *intoken = out->intoken;
    
    /* In case we need to restart on the slow-path */
    size_t orig_cursor = cursor;
    size_t orig_wire_len = out->wire.len;
    
    /* Accumulate anything unexpected in the fast-path */
    int err = 0;
    
    /* Save these for the final result */
    unsigned rrttl = out->state.default_ttl;
    unsigned rrclass = 1; /* default IN */
    unsigned rrtype = 0;
    
    unsigned length;
    
    
    /*
     * FIELD #1: owner name
     */
    zone_atom_name_fast(data, cursor, max, out);
    if (!out->is_fqdn) {
        /* if not fully qualified it, append the origin */
        wire_append_bytes(out, out->state.origin, out->state.origin_length);
    }
    out->ownername_length = out->wire.len - orig_wire_len;

    /* goto next token */
    cursor += classified_length(intoken, cursor);
    cursor += classified_length(whitespace, cursor);
    length = classified_length(intoken, cursor);
    
    /*
     * FIELD#2: TTL
     */
    if (is_digit(data[cursor])) {
        parse_ttl_fast(data, cursor, max, &rrttl, &err);

        /* goto next token */
        cursor += length;
        cursor += classified_length(whitespace, cursor);
        length = classified_length(intoken, cursor);
    }
        

    unsigned idx;
    
    
    /*
     * FIELD#3: CLASS, maybe TYPE
     */
    if (length == 2 && data[cursor] == 'I' && data[cursor+1] == 'N') {
        /* happy path */
        idx = 1;
        rrtype = 1;
    } else {
        idx = zone_type2_lookup(data + cursor, length, &rrtype);
    }
    if (idx <= 5) {
        err |= (idx == 0);
        
        /* it’s CLASS */
        rrclass = rrtype;
        
        /* goto next token */
        cursor += length;
        cursor += classified_length(whitespace, cursor);
        length = classified_length(intoken, cursor);

        /*
         * FIELD#4: TYPE
         */
        idx = zone_type2_lookup(data + cursor, length, &rrtype);
    }
    out->rrtype.value = rrtype;
    out->rrtype.idx = idx;
    
    /* goto next token */
    cursor += length;
    cursor += classified_length(whitespace, cursor);
    
    /*
     * Check for errors
     */
    err |= (idx == 0);
    err |= (cursor <= orig_cursor);
    err |= (data[cursor] == '(');
    err |= (data[cursor] == ')');
    err |= (data[cursor] == ';');
    if (err)
        goto slow_path;
 
 
    /* Write to the output buffer. We have done bounds check
     * for this buffer before we get to this point. */
    uint8_t *dst = out->wire.buf + out->wire.len;
    store_be16(dst + 0, rrtype);
    store_be16(dst + 2, rrclass);
    store_be32(dst + 4, rrttl);
    out->wire.len += 8;

    return cursor;

slow_path:
    out->wire.len = orig_wire_len;
    return zone_slow_header(data, orig_cursor, max, out, depth);
}


void zone_fast_header_init(int backend) {
    zone_fast_classify_init(backend);
    zone_atom_name4_init(backend);
}
