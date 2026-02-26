/* zone-parse-record.c
 *
 * See zone-parse-record.h for the full specification and pipeline description.
 *
 * Contains zone_parse_quicktest() with 20 common record test vectors.
 */

#include "zone-parse-record.h"
#include "zone-atom-name.h"
#include "zone-parse-types.h"
#include "zone-atom.h"
#include "zone-atom-name.h"

#include <string.h>  /* memset, memcmp */
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>

#ifndef ZONE_ERR_INTERNAL
#define ZONE_ERR_INTERNAL 0x7FFF
#endif

#ifndef ZONE_ERR_OVERFLOW
#define ZONE_ERR_OVERFLOW 0x7FFE
#endif

#ifndef ZONE_ERR_BADTYPE
#define ZONE_ERR_BADTYPE  0x7FFD
#endif



void copy_name(const unsigned char *name, size_t length, wire_record_t *out) {
    ;
}
size_t ERROR(zone_state_t *state, size_t max, int err_code, size_t err_cursor) {
    return max+1;
}
void wire_append_uint8(wire_record_t *out, unsigned val) {
    if (out->wire.len + 1 < out->wire.max) {
        out->wire.buf[out->wire.len+0] = (unsigned char)(val);
        out->wire.len += 1;
    } else if (out->err.code == 0) {
        out->err.code = ZONE_ERROR_WIRE_OVERFLOW;
    }
}

void wire_append_uint16(wire_record_t *out, unsigned val) {
    if (out->wire.len + 2 < out->wire.max) {
        out->wire.buf[out->wire.len+0] = (unsigned char)(val >> 8);
        out->wire.buf[out->wire.len+1] = (unsigned char)(val & 0xFF);
        out->wire.len += 2;
    } else if (out->err.code == 0) {
        out->err.code = ZONE_ERROR_WIRE_OVERFLOW;
    }
}
void wire_append_uint32(wire_record_t *out, unsigned val) {
    if (out->wire.len + 4 < out->wire.max) {
        out->wire.buf[out->wire.len+0] = (unsigned char)(val >> 24);
        out->wire.buf[out->wire.len+1] = (unsigned char)(val >> 16);
        out->wire.buf[out->wire.len+2] = (unsigned char)(val >> 8);
        out->wire.buf[out->wire.len+3] = (unsigned char)(val & 0xFF);
        out->wire.len += 4;
    } else if (out->err.code == 0) {
        out->err.code = ZONE_ERROR_WIRE_OVERFLOW;
    }
}
void wire_append_bytes(wire_record_t *out, const unsigned char *data, size_t length) {
    if (out->wire.len + length < out->wire.max) {
        memcpy(out->wire.buf + out->wire.len, data, length);
        out->wire.len += length;
    } else if (out->err.code == 0) {
        out->err.code = ZONE_ERROR_WIRE_OVERFLOW;
    }
}


static size_t skip_remainder(const char *data, size_t cursor, size_t max) {
    while (data[cursor] == ' ' || data[cursor] == '\t')
        cursor++;
    if (data[cursor] == ';') {
        while (data[cursor != '\n'])
            cursor++;
    }
    if (data[cursor] == '\r')
        cursor++;
    if (data[cursor] != '\n')
        cursor = max + 1;
    else
        cursor++;
    return cursor;
}
/**
 * Parse the $ORIGIN or $TTL field.
 * TODO: $INCLUDE and $GENERATE
 * So far, we are parsing for benchmarking purposes. Eventually we'll figure out
 * what to do with the $INCLUDE, probably by giving a callback.
 */
static size_t
parse_directive(const char *data, size_t cursor, size_t max,
                  zone_state_t *state, wire_record_t *out) {
    wire_record_t out2 = {0};
    unsigned char origin[256 + 64];
    out2.wire.buf = origin;
    out2.wire.max = 256;
    out2.state.origin = state->origin;
    out2.state.origin_length = state->origin_length;
    
    if (strncasecmp("$ORIGIN", data+cursor, 7)==0) {
        cursor++;
        while (data[cursor] == ' ' || data[cursor] == '\t')
            cursor++;
        cursor = zone_parse_name0(data, cursor, max, &out2);
        memcpy(state->origin, out2.wire.buf, out2.wire.len);
        state->origin_length = out2.wire.len;
        cursor = skip_remainder(data, cursor, max);
    } else if (strncasecmp("$TTL", data+cursor, 4) == 0) {
        unsigned ttl = 0;
        int err = 0;
        size_t next;
        next = parse_ttl_seconds(data, cursor, max, &ttl, &err);
        if (err) {
            PARSE_ERR(1, cursor, max, out);
        } else {
            cursor = skip_remainder(data, next, max);
        }
    } else {
        PARSE_ERR(1, cursor, max, out);
    }
    return cursor;
}
#include <stdint.h>

/* Byte classification values */
enum byte_class {
    BC_OTHER      = 0,
    BC_AT         = 1,  /* '@'  */
    BC_DOLLAR     = 2,  /* '$'  */
    BC_SEMICOLON  = 3,  /* ';'  */
    BC_LPAREN     = 4,  /* '('  */
    BC_CR         = 5,  /* '\r' */
    BC_NL         = 6,  /* '\n' */
    BC_SPACE      = 7,  /* ' ' and '\t' */
    BC_STAR       = 8   /* '*'  */
};

/* 256-entry lookup table */
static const uint8_t byte_class_table[256] = {
    /* 0x00..0x07 */ 0,0,0,0,0,0,0,0,
    /* 0x08..0x0F */ 0,BC_SPACE,BC_NL,0,0,BC_CR,0,0,
    /* 0x10..0x17 */ 0,0,0,0,0,0,0,0,
    /* 0x18..0x1F */ 0,0,0,0,0,0,0,0,
    /* 0x20..0x27 */ BC_SPACE,0,BC_STAR,0,BC_DOLLAR,0,0,0,
    /* 0x28..0x2F */ BC_LPAREN,0,0,0,0,0,0,0,
    /* 0x30..0x37 */ 0,0,0,0,0,0,0,0,
    /* 0x38..0x3F */ 0,0,0,BC_SEMICOLON,0,0,0,0,

    /* 0x40..0x47 */ BC_AT,0,0,0,0,0,0,0,
    /* 0x48..0x4F */ 0,0,0,0,0,0,0,0,
    /* 0x50..0x57 */ 0,0,0,0,0,0,0,0,
    /* 0x58..0x5F */ 0,0,0,0,0,0,0,0,
    /* 0x60..0x67 */ 0,0,0,0,0,0,0,0,
    /* 0x68..0x6F */ 0,0,0,0,0,0,0,0,
    /* 0x70..0x77 */ 0,0,0,0,0,0,0,0,
    /* 0x78..0x7F */ 0,0,0,0,0,0,0,0,

    /* 0x80..0x87 */ 0,0,0,0,0,0,0,0,
    /* 0x88..0x8F */ 0,0,0,0,0,0,0,0,
    /* 0x90..0x97 */ 0,0,0,0,0,0,0,0,
    /* 0x98..0x9F */ 0,0,0,0,0,0,0,0,
    /* 0xA0..0xA7 */ 0,0,0,0,0,0,0,0,
    /* 0xA8..0xAF */ 0,0,0,0,0,0,0,0,
    /* 0xB0..0xB7 */ 0,0,0,0,0,0,0,0,
    /* 0xB8..0xBF */ 0,0,0,0,0,0,0,0,
    /* 0xC0..0xC7 */ 0,0,0,0,0,0,0,0,
    /* 0xC8..0xCF */ 0,0,0,0,0,0,0,0,
    /* 0xD0..0xD7 */ 0,0,0,0,0,0,0,0,
    /* 0xD8..0xDF */ 0,0,0,0,0,0,0,0,
    /* 0xE0..0xE7 */ 0,0,0,0,0,0,0,0,
    /* 0xE8..0xEF */ 0,0,0,0,0,0,0,0,
    /* 0xF0..0xF7 */ 0,0,0,0,0,0,0,0,
    /* 0xF8..0xFF */ 0,0,0,0,0,0,0,0
};


/*
                                1  1  1  1  1  1
  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                               |
/                                               /
/                      NAME                     /
|                                               |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                      TYPE                     |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                     CLASS                     |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                      TTL                      |
|                                               |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                   RDLENGTH                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
/                     RDATA                     /
/                                               /
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

 */
size_t
zone_parse_record(const char *data, size_t cursor, size_t max,
                         zone_state_t *state, wire_record_t *out) {
    unsigned depth = 0;
    size_t rrlength_offset = 0;

    out->line_count = 0;

again:
    
    /*
     * 99% this hits the default/OTHER case, where we just
     * parse an owner-name. The other characters are other
     * options.
     */
    switch (byte_class_table[data[cursor]]) {
    case BC_SPACE: /* space and tab */
    case BC_LPAREN: /* '(' */
        /*
         * Skip any whitespace
         */
        cursor = zone_parse_space(data, cursor, max, out, &depth);
        copy_name(state->prior_name, state->prior_name_length, out);
        out->name_length = state->prior_name_length;
        break;
    case BC_DOLLAR: /* '$' */
        cursor = parse_directive(data, cursor, max, state, out);
        goto again;
    case BC_SEMICOLON: /* ';' */
        cursor = zone_scan_eol(data, cursor, max);
        if (cursor >= max)
            return cursor;
        assert(data[cursor] == '\n');
        cursor++;
        if (cursor >= max)
            return cursor;
        out->line_count++;
        goto again;
        break;
    case BC_CR: /* '\r' */
        if (data[cursor+1] != '\n') {
            return PARSE_ERR(1, cursor, max, out);
        }
        cursor++;
        /* fall through */
    case BC_NL: /* '\n' */
        out->line_count++;
        cursor++;
        goto again;
        break;
    case BC_AT: /* '@' */
    case BC_STAR: /* '*' */
        cursor = zone_parse_name0(data, cursor, max, out);
        out->name_length = out->wire.len;
        break;
    case BC_OTHER:
    default:
        /*
         * Step 1: owner name -> wire
         */
        cursor = zone_atom_name4(data, cursor, max, out);
        out->name_length = out->wire.len;
        if (!out->is_fqdn) {
            /* if not fully qualified it, append the origin */
            wire_append_bytes(out, out->state.origin, out->state.origin_length);
            out->name_length += out->state.origin_length;
        }
        break;
    }
        
    
    /*
     * Step #2 get TTL + CLASS + TYPE. the TTL and CLASS may be optional,
     * but the TYPE is required. It may be a TYPEnnn though.
     */
    cursor = zone_parse_header2(data, cursor, max, out, &depth);
    rrlength_offset = out->wire.len; /* put length here after parsing */
    wire_append_uint16(out, 0);

    /*
     * Step 3: Parse the contents of the record
     */
    if (data[cursor] == '\\' && data[cursor+1] == '#') {
        cursor = zone_parse_GENERIC(data, cursor, max, out, &depth);
    } else {
        const struct zone_atom_type *t = zone_type2_by_index(out->rrtype.idx);
        cursor = t->parse(data, cursor, max, out, &depth);
    }
    cursor = zone_parse_finish(data, cursor, max, out, &depth);
    if (out->err.code || cursor > max)
        return cursor + 1;

    /*
     * Step 4: Set the proper
     */
    out->wire.buf[rrlength_offset+0] = (unsigned char)((out->wire.len - rrlength_offset - 2)>>8);
    out->wire.buf[rrlength_offset+1] = (unsigned char)((out->wire.len - rrlength_offset - 2)>>0);
   
    state->line_number += out->line_count;
    return cursor;
}

