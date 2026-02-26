
// zone-atom-name5.c
//
// =============================== FULL SPEC ==================================
// zone_atom_name5(): slow, safe, simple DNS name atom parser for zonefiles.
// Fallback used by the fast name4 parser.
//
// Inputs:
//   - data: pointer to zonefile text buffer
//   - i:    starting offset into data (name begins at data[i])
//   - max:  maximum offset (exclusive) for safe access
//
// Outputs:
//   - out_wire[256]: wire format name (labels: len byte + label bytes, ending in 0)
//   - zone_status_t *st:
//       * wire_len: length of out_wire written
//       * err_code: 0 if ok, else nonzero
//       * err_offset: best-effort offset from initial i where error occurred
//       * flags: includes ZONE_NAME_F_FQDN if a trailing dot produced a root label
//
// Return value:
//   - bytes consumed for the name text (does NOT include the terminating character)
//   - On error, returns 0 and st->err_code is nonzero.
//
// Parsing rules:
//   - Valid unescaped name characters: [A-Za-z0-9_-]
//   - Dots '.' separate labels.
//   - Terminator is any character that is NOT a valid name character, '.' or '\' escape.
//     This function does NOT validate which terminator is acceptable; caller decides.
//   - No empty labels except the final root label implied by a trailing dot.
//   - Always emit a root label (0) at the end in wire format.
//
// Escapes:
//   - Backslash '\' introduces an escape, matching the fixed-width decimal style:
//       * \DDD : exactly three DECIMAL digits (0-9), value 0..255
//       * \X   : otherwise, the next character literally (single-char escape)
//     parse_escape() takes (data, i, max, *out_byte) and returns bytes consumed.
//     On error, returns 0.
//   - After decoding an escape, we call is_valid_hostchar(out_byte) to reject
//     control chars and DEL. This is the ONLY place such checking is performed.
//
// Label length / bounds:
//   - Each label length must be <= 63 (error otherwise).
//   - Total wire name must fit in out_wire[256] (error otherwise).
//
// Implementation goals:
//   - Clean, simple, obvious control flow.
// ============================================================================
#include "zone-parse.h"
#include <stdio.h>
#include <string.h>

#if 0
/*
 * Zonefile "space" / delimiter characters:
 *   ' '  (0x20)
 *   '\t' (0x09)
 *   '\r' (0x0d)
 *   '\n' (0x0a)
 *   '('  (0x28)
 *   ')'  (0x29)
 *   ';'  (0x3b)
 */
static const unsigned char zone_space_table[256] = {
    /* 0x00–0x07 */ 0,0,0,0,0,0,0,0,
    /* 0x08–0x0F */ 0,1,1,0,0,1,0,0,   /* \t=0x09, \n=0x0a, \r=0x0d */
    /* 0x10–0x17 */ 0,0,0,0,0,0,0,0,
    /* 0x18–0x1F */ 0,0,0,0,0,0,0,0,
    /* 0x20–0x27 */ 1,0,0,0,0,0,0,0,   /* space=0x20 */
    /* 0x28–0x2F */ 1,1,0,0,0,0,0,0,   /* '('=0x28, ')'=0x29 */
    /* 0x30–0x37 */ 0,0,0,0,0,0,0,0,
    /* 0x38–0x3F */ 0,0,0,1,0,0,0,0,   /* ';'=0x3b */
    /* 0x40–0x47 */ 0,0,0,0,0,0,0,0,
    /* 0x48–0x4F */ 0,0,0,0,0,0,0,0,
    /* 0x50–0x57 */ 0,0,0,0,0,0,0,0,
    /* 0x58–0x5F */ 0,0,0,0,0,0,0,0,
    /* 0x60–0x67 */ 0,0,0,0,0,0,0,0,
    /* 0x68–0x6F */ 0,0,0,0,0,0,0,0,
    /* 0x70–0x77 */ 0,0,0,0,0,0,0,0,
    /* 0x78–0x7F */ 0,0,0,0,0,0,0,0,
    /* 0x80–0xFF */
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
};

static inline int is_space_char(unsigned char c)
{
    return zone_space_table[c];
}
#endif

/* ------------------------------ helpers ----------------------------------- */

static inline int is_valid_name_char(unsigned char c)
{
    if (c >= (unsigned char)'0' && c <= (unsigned char)'9') return 1;
    if (c >= (unsigned char)'A' && c <= (unsigned char)'Z') return 1;
    if (c >= (unsigned char)'a' && c <= (unsigned char)'z') return 1;
    if (c == (unsigned char)'-' || c == (unsigned char)'_') return 1;
    return 0;
}

static inline int is_illegal_byte(unsigned char c)
{
    // Conservative: reject control chars and DEL
    return (c < 0x20u) || (c == 0x7Fu);
}
static inline int is_digit(unsigned char c)
{
    return (c >= (unsigned char)'0' && c <= (unsigned char)'9');
}

/* ------------------------------ parse_escape ------------------------------ */
/* Returns bytes consumed (>=2) starting at data[i] where data[i] == '\\'.
   On error returns 0. */
static size_t
parse_escape(const char *data, size_t i, size_t max, uint8_t *out_byte)
{
    if (i >= max) return 0;
    if ((unsigned char)data[i] != (unsigned char)'\\') return 0;

    /* Need at least one character after '\' */
    if (i + 1 >= max) return 0;

    unsigned char c1 = (unsigned char)data[i + 1];

    /* \DDD : exactly three decimal digits */
    if (i + 3 < max &&
        is_digit(c1) &&
        is_digit((unsigned char)data[i + 2]) &&
        is_digit((unsigned char)data[i + 3]))
    {
        unsigned d1 = (unsigned)(data[i + 1] - '0');
        unsigned d2 = (unsigned)(data[i + 2] - '0');
        unsigned d3 = (unsigned)(data[i + 3] - '0');

        unsigned val = d1 * 100u + d2 * 10u + d3;

        if (val > 255u) return 0;

        *out_byte = (uint8_t)val;
        return 4; /* '\'+3 digits */
    }

    /* \X : literal next char */
    *out_byte = (uint8_t)c1;
    return 2;
}

/* ------------------------------ zone_atom_name5 --------------------------- */


size_t
zone_atom_name5(const char *data, size_t cursor, size_t max,
                struct wire_record_t *out)
{
    int err = 0;


    /*
     * Special case, empty name with just one empty label, the ".",
     * indicating <root>
     */
    if (data[cursor] == '.' && cursor+1 < max && !is_valid_name_char(data[cursor+1])) {
        /* empty name*/
        wire_append_uint8(out, 0);
        return cursor + 1;
    }
    
    /* Reserve space for first label length byte */
    size_t lab_len_pos = out->wire.len;
    size_t lab_len = 0;

    wire_append_uint8(out, 0);

    while (cursor < max) {
 
        /* Copy the label */
        while (is_valid_name_char(data[cursor])) {
            wire_append_uint8(out, data[cursor]);
            lab_len++;
            cursor++;
        }

        unsigned char c = (unsigned char)data[cursor];

        /* dot: end of label */
        if (c == (unsigned char)'.') {
            if (lab_len == 0)
                return PARSE_ERR(ZONE_ERROR_LABEL_EMPTY, cursor, max, out);
            if (lab_len > 63)
                return PARSE_ERR(ZONE_ERROR_LABEL_LONG, cursor, max, out);
            
            out->wire.buf[lab_len_pos] = (uint8_t)lab_len;
            cursor++; /* consume '.' */
            
            lab_len_pos = out->wire.len;
            lab_len = 0;
            wire_append_uint8(out, 0);
            continue;
        }

        /* escape */
        if (c == (unsigned char)'\\') {
            uint8_t outc = 0;
            size_t n = parse_escape(data, cursor, max, &outc);
            if (n == 0)
                return PARSE_ERR(ZONE_ERROR_ESCAPE_BAD, cursor, max, out);

            /* Only time we check control/DEL */
            if (is_illegal_byte(outc))
                return PARSE_ERR(ZONE_ERROR_ESCAPE_BAD, cursor, max, out);
            wire_append_uint8(out, outc);
            lab_len++;
            cursor += n;
            continue;
        }

        /* Any other char terminates the name (caller validates terminator) */
        break;
    }

    if (lab_len > 63)
        return PARSE_ERR(ZONE_ERROR_LABEL_LONG, cursor, max, out);
    
    out->wire.buf[lab_len_pos] = (uint8_t)lab_len;

    out->is_fqdn = (lab_len == 0);
    
    /* If there was an overflow */
    if (err)
        return PARSE_ERR(err, cursor, max, out);
    
    return cursor;
}

#include <ctype.h>

static void dump_wire(const unsigned char *wire, size_t wire_len) {
    printf("\"");
    for (unsigned i = 0; i < wire_len; i++) {
        char c = wire[i];
        if (isalnum(c&0xFF) || c == '-' || c == '_')
            printf("%c", c);
        else if (isprint(c&0xFF))
            printf("\\%c", c);
        else
            printf("\\%03o", c);
    }
    printf("\"\n");
}

void zone_atom_name5_init(int backend) {
    /* nothing to do */
    return;
}
static struct test_case_t {
    const char *input;
    int in_length;
    const char *output;
    size_t out_length;
    size_t consumed;
    unsigned char is_fqdn;
} test_cases[] = {
    {"www.example.com. IN A 1.2.3.4", 16, "\3www\7example\3com\0", 17, 20, 1},
    {"www\\046example\\.com\tIN A 1.2.3.4", -1, "\x0fwww.example.com", 16, 20, 0},
    {"www.example.com. IN A 1.2.3.4", -1, "\3www\7example\3com\0", 17, 20, 1},
    {"www.example.com IN A 1.2.3.4", 15, "\3www\7example\3com\0", 16, 20, 0},
    {"www.example.com. IN A 1.2.3.4", 16, "\3www\7example\3com\0", 17, 20, 1},
    {0}
};
int zone_atom_name5_quicktest(void) {
    int err = 0;
    int i;
    
    for (i=0; test_cases[i].input; i++) {
        struct test_case_t *test = &test_cases[i];
        const char *in = test->input;
        int in_length = test_cases[i].in_length;
        const unsigned char *exp = (uint8_t*)test->output;
        size_t exp_len = test_cases[i].out_length;
        unsigned exp_fqdn = test_cases[i].is_fqdn;
        
        if (in_length == -1)
            in_length = (int)strlen((char*)in);
        
        /*
         * Initialize 'out' structure
         */
        wire_record_t out = {0};
        uint8_t buf[256+1024];
        out.wire.buf = buf;
        out.wire.max = 256;
        
        /*
         * Run test
         */
        size_t consumed = zone_atom_name5(in, 0, in_length, &out);
        
        if (consumed == 0) {
            printf("[-] name5:%d: empty name, err=%d\n", i, (int)out.err.code);
            err++;
            continue;
        }
        
        if (out.wire.len != exp_len) {
            fprintf(stderr, "[-] name5:%d: output length mismatch, found %u, expected %u\n",
                    i, (unsigned)out.wire.len, (unsigned)exp_len);
            dump_wire(out.wire.buf, out.wire.len);
            err++;
            continue;
        }
        if (memcmp(out.wire.buf, exp, exp_len) != 0) {
            unsigned j;
            fprintf(stderr, "[-] name5:%d: output name mismatch\n", i);
            
            printf(" found: ");
            for (j=0; j<out.wire.len; j++)
                fprintf(stderr, " %02x", out.wire.buf[j]);
            printf("  ");
            for (j=0; j<out.wire.len; j++)
                fprintf(stderr, "%c", out.wire.buf[j]);
            
            
            fprintf(stderr, "\n");
            printf("expect: ");
            for (j=0; j<exp_len; j++)
                fprintf(stderr, " %02x", exp[j]);
            printf("  ");
            for (j=0; j<exp_len; j++)
                fprintf(stderr, "%c", exp[j]);
            
            fprintf(stderr, "\n");
            err++;
            continue;
        }
        
        if (out.is_fqdn != exp_fqdn) {
            fprintf(stderr, "[-] name5:%d: FQDN mismatch\n", i);
            err++;
            continue;
        }
    }
    return 0;
}
