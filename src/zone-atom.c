#include "zone-atom.h"
#include <assert.h>

size_t zone_parse_finish(const char *data, size_t cursor, size_t max, struct wire_record_t *out, unsigned *depth) {
    if (data[cursor] == '\n') {
        out->line_count++;
    } else {
        return PARSE_ERR(ZONE_ERROR_IMPOSSIBLE, cursor, max, out);
    }
    return cursor + 1;
}

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

/**
 * A DNS name must end in a valid space character. The allowed  characters are
 * ' ' a space
 * '\t' tab character
 * '(' starts a multiline record, converted to a ' ' space logically
 * ')' ends a multiline portion of a record, converted to a space,too
 * ';' starts a comment, also converted to a space logically
 * '\r' ends a line (along with an immediately following '\n')
 * '\n' ends a line
 */
static inline int is_space_char(unsigned char c)
{
    /* Test with a single table lookup. It's unclear whether this
     * is faster, as this consumes a 64-byte cacheline in the L1 cache.
     * While we have 7 characters to test for, such tests can be done
     * in parallel in one or two clock cycles on today's CPUs. The
     * difference in speed is so far unmeasurable in my tests.
     */
    return zone_space_table[c];
}
size_t
zone_parse_space(const char *data, size_t cursor, size_t max,
                  struct wire_record_t *out,
                  unsigned *depth) {
    if (!is_space_char(data[cursor])) {
        return PARSE_ERR(ZONE_ERROR_EXPECTED_WHITESPACE, cursor, max, out);
    }
    while (data[cursor] == ' ' || data[cursor] == '\t')
        cursor++;
    if (!is_space_char(data[cursor]))
        return cursor;
    for (;;) {

        /* fast skip typical space */
        while (data[cursor] == ' ' || data[cursor] == '\t')
            cursor++;

        unsigned char c = (unsigned char)data[cursor];
        
        /* Trigger: comment start ';' */
        if (c == ';') {
            cursor = zone_scan_eol(data, cursor, max);
            assert(data[cursor] == '\n');
            if (*depth == 0)
                return cursor;
            out->line_count++;
            cursor++;
            continue;
        }

        /* Trigger: '(' increments depth, consume, continue */
        if (c == '(') {
            (*depth)++;
            cursor++;
            continue;
        }

        /* Trigger: ')' decrements depth, consume, continue */
        if (c == ')') {
            (*depth)--;
            cursor++;
            continue;
        }

        if (c == '\r') {
            if (data[cursor+1] != '\n') {
                return cursor; /* halt at non-linebreak CR */
            }
            out->line_count++;
            if (*depth == 0)
                return cursor + 1;
            else
                cursor += 2;
            continue;
        }
        
        /* Trigger: newline */
        if (c == '\n') {
            if (*depth == 0)
                return cursor;
            out->line_count++;
            cursor++;
            continue;
        }

        /* Otherwise we are at token start (non-whitespace, non-trigger). */
        return cursor;
    }
}

/*
 * Called on startup to do a quick unit/regression test. It's not
 * comprehensive, only testing some basic functionality.
 */
int zone_atom_quicktest(void) {
    int err = 0;
    
    
    //err += zone_atom_base64a_quicktest();
    //err += zone_atom_base64b_quicktest();
    err += zone_atom_base64c_quicktest();
    err += zone_atom_base64d_quicktest();
    err += zone_atom_name5_quicktest();
    err += zone_atom_name4_quicktest();
    err += zone_atom_ipv6_quicktest();
    err += zone_atom_expire2_quicktest();

    if (err == 0) {
        fprintf(stderr, "[+] atom: test success!\n");
    } else {
        fprintf(stderr, "[-] atom: tests failed :-(\n");
    }
    return err;
}

extern void zone_atom_base64c_init(int backend);
extern void zone_atom_base64d_init(int backend);
extern void zone_atom_expire2_init(int backend);

void
zone_atom_init(int backend) {
    zone_atom_base64c_init(backend);
    zone_atom_base64d_init(backend);
    zone_atom_expire2_init(backend);
}
