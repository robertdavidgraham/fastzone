#include "zone-atom.h"
#include "zone-parse.h"
#include "zone-parse-record.h"
#include "zone-error.h"



static inline int is_digit(char c) {
    return (c >= (unsigned char)'0' && c <= (unsigned char)'9');
}

size_t
zone_atom_int8(const char *data, size_t cursor, size_t max,
              struct wire_record_t *out) {
    uint64_t number = 0;
    
    if (cursor > max)
        return max + 1;
    for (;;) {
        char c = data[cursor];
        if (is_digit(c)) {
            number *= 10;
            number += c - '0';
            cursor++;
        } else
            break;
    }
    if (number > 0xFF) {
        PARSE_ERR(1, cursor, max, out);
    }

    wire_append_uint8(out, (uint8_t)number);
    
    return cursor;
}

size_t
zone_atom_int8x(const char *data, size_t cursor, size_t max,
              struct wire_record_t *out, unsigned *x) {
    uint64_t number = 0;
    
    if (cursor > max)
        return max + 1;
    for (;;) {
        char c = data[cursor];
        if (is_digit(c)) {
            number *= 10;
            number += c - '0';
            cursor++;
        } else
            break;
    }
    *x = (unsigned)number;
    if (number > 0xFF) {
        PARSE_ERR(1, cursor, max, out);
    }
    
    wire_append_uint8(out, (uint8_t)number);
    
    return cursor;
}

size_t
zone_atom_int16(const char *data, size_t cursor, size_t max,
              struct wire_record_t *out) {
    uint64_t number = 0;
    
    for (;;) {
        char c = data[cursor];
        if (is_digit(c)) {
            number *= 10;
            number += c - '0';
            cursor++;
        } else
            break;
    }
    if (number > 0xFFFF) {
        PARSE_ERR(1, cursor, max, out);
    }
    
    wire_append_uint16(out, (uint16_t)number);
    
    return cursor;
}
size_t
zone_atom_int32(const char *data, size_t cursor, size_t max,
              struct wire_record_t *out) {
    uint64_t number = 0;
    
    if (cursor > max)
        return max + 1;
    for (;;) {
        char c = data[cursor];
        if (is_digit(c)) {
            number *= 10;
            number += c - '0';
            cursor++;
        } else
            break;
    }
    if (number > 0xFFFFffff) {
        PARSE_ERR(1, cursor, max, out);
    }

    wire_append_uint32(out, (uint32_t)number);
    
    return cursor;
}
