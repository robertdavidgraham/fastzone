/* zone-parse-record.c
 *
 * See zone-parse-record.h for the full specification and pipeline description.
 *
 * Contains zone_parse_quicktest() with 20 common record test vectors.
 */

#include "zone-parse-record.h"
#include "zone-fast-header.h"
#include "zone-atom-name.h"
#include "zone-parse-types.h"
#include "zone-atom.h"
#include "zone-atom-name.h"

#include <string.h>  /* memset, memcmp */
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>

#ifdef __GNUC__
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"
#endif

#ifdef _MSC_VER
#define strcasecmp _stricmp
#define strncasecmp _strnicmp
#endif

#ifndef ZONE_ERR_INTERNAL
#define ZONE_ERR_INTERNAL 0x7FFF
#endif

#ifndef ZONE_ERR_OVERFLOW
#define ZONE_ERR_OVERFLOW 0x7FFE
#endif

#ifndef ZONE_ERR_BADTYPE
#define ZONE_ERR_BADTYPE  0x7FFD
#endif





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
zone_fast_record(const char *data, size_t cursor, size_t max,
                         zone_state_t *state, wire_record_t *out) {
    unsigned depth = 0;
    size_t rrlength_offset = 0;
    size_t orig_wire_len = out->wire.len;
    size_t orig_cursor = cursor;

    out->line_count = 0;


    
    /*
     * 99% this hits the default/OTHER case, where we just
     * parse an owner-name. The other characters are other
     * options.
     */
    switch (byte_class_table[(unsigned char)data[cursor]]) {
    case BC_SPACE: /* space and tab */
    case BC_LPAREN: /* '(' */
    case BC_DOLLAR: /* '$' */
    case BC_SEMICOLON: /* ';' */
    case BC_CR: /* '\r' */
    case BC_NL: /* '\n' */
    case BC_AT: /* '@' */
    case BC_STAR: /* '*' */
        return zone_slow_record(data, cursor, max, state, out);
    case BC_OTHER:
    default:
        break;
    }
    
    /*
     * Get "header": OWNER TTL CLASS TYPE
     */
    cursor = zone_fast_header(data, cursor, max, out, &depth);
    
    /*
     * Reserve 2-bytes in the wire-buffer for an rrlength field
     * for what will be parsed next.
     */
    rrlength_offset = out->wire.len; /* put length here after parsing */
    out->wire.len += 2;

    /*
     * RRTYPE
     *  It's at this point that we experience a branch-misprediction
     *  due to being unable to predict the type that we need to parse.
     */
    if (data[cursor] == '\\' && data[cursor+1] == '#') {
        cursor = zone_parse_GENERIC(data, cursor, max, out, &depth);
    } else {
        const struct zone_atom_type *t = zone_type2_by_index(out->rrtype.idx);
        cursor = t->parse(data, cursor, max, out, &depth);
    }
    
    /*
     * If we don't end at a newline, then we need to discard the
     * happy-path parsing and go back and do a slow-path parsing.
     */
    if (data[cursor] == '\r')
        cursor++;
    int err = (data[cursor] != '\n');
    err |= out->err.code; /* should be no error */
    err |= depth; /* should be zero */
    err |= (out->wire.len > out->wire.max);
    err |= (cursor > max);
    if (err) {
        out->wire.len = orig_wire_len;
        cursor = orig_cursor;
        return zone_slow_record(data, cursor, max, state, out);
    }
    
    /*
     * Write the RRLENGTH field
     */
    out->wire.buf[rrlength_offset+0] = (unsigned char)((out->wire.len - rrlength_offset - 2)>>8);
    out->wire.buf[rrlength_offset+1] = (unsigned char)((out->wire.len - rrlength_offset - 2)>>0);
   
    out->line_count++;
    state->line_number += out->line_count;
    return cursor;
}


