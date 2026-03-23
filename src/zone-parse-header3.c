
#include <stddef.h>
#include <stdint.h>

#include "zone-parse.h"
#include "util-simd.h"
#include "zone-parse-token.h"

/* ------------ wire write helpers (big-endian) ------------ */
static inline void store_be16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v >> 0);
}
static inline void store_be32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)(v >> 0);
}


static int is_digit(char c) {
    return ('0' <= c && c <= '9');
}

/* ------------ happy-path header parse (single classify, straight line) ------------ */

size_t
zone_parse_header3(const char *data, size_t cursor, size_t max,
                   struct wire_record_t *out,
                   unsigned *depth)
{
    size_t orig_cursor = cursor; /* save in case of slow-path*/
    int err = 0; /* accumulate errors */
    
    unsigned rrttl = out->state.default_ttl;
    unsigned rrclass = 1; /* default IN */
    unsigned rrtype = 0;

    
    /*
     * Do the initialize classification, skip any spaces, and
     * grab the length of the first token.
     */
    parsetokens_t tokens = {0};
    size_t length = parse_space_length(data, cursor, &tokens);
    cursor += length;
    length = parse_token_length(data, cursor, &tokens);
    
    /*
     * TTL
     */
    if (is_digit(data[cursor])) {
        parse_ttl_fast(data, cursor,
                          max,
                          &rrttl,
                          &err);

        /* skip token */
        cursor += length;
        cursor += parse_space_length(data, cursor, &tokens);
        length = parse_token_length(data, cursor, &tokens);
    }
        

    unsigned idx;
    
    
    /*
     * CLASS
     */
    if (length == 2 && data[cursor] == 'I' && data[cursor+1] == 'N') {
        /* happy path */
        idx = 1;
        rrtype = 1;
    } else {
        idx = zone_type2_lookup(data + cursor, length, &rrtype);
    }
    if (idx < 4) {
        err |= (idx == 0);
        
        /* it’s CLASS */
        rrclass = rrtype;
        
        /* skip token */
        cursor += length;
        cursor += parse_space_length(data, cursor, &tokens);
        length = parse_token_length(data, cursor, &tokens);

        idx = zone_type2_lookup(data + cursor, length, &rrtype);
    }
    out->rrtype.value = rrtype;
    out->rrtype.idx = idx;
    
    /* skip token */
    cursor += length;
    cursor += parse_space_length(data, cursor, &tokens);
        
    /*
     * Check for errors
     */
    err |= (idx == 0);
    err |= (cursor == orig_cursor);
    err |= (data[cursor] == '(');
    err |= (data[cursor] == ')');
    err |= (data[cursor] == ';');
    if (err)
        goto slow_path;
 
 
    uint8_t *dst = out->wire.buf + out->wire.len;
    store_be16(dst + 0, (uint16_t)rrtype);
    store_be16(dst + 2, (uint16_t)rrclass);
    store_be32(dst + 4, (uint32_t)rrttl);
    out->wire.len += 8;

    return cursor;

slow_path:
    return zone_parse_header(data, orig_cursor, max, out, depth);
}
