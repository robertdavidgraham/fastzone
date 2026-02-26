#include "zone-parse.h"
#include "zone-parse-record.h"
#include "zone-error.h"


static inline char to_lower(char c) {
  if (c >= 'A' && c <= 'Z')
      return (c + 32);
  return c;
}

static inline int is_digit(char c) {
    return (c >= (unsigned char)'0' && c <= (unsigned char)'9');
}

size_t
parse_ttl_seconds(const char *data, size_t cursor, size_t max,
                         unsigned *ttl_out, int *err) {
    uint64_t total = 0;
    
    while (is_digit(data[cursor])) {
        
        /* TTLs may be integers or look like 1d5h, consisting
         * over multiple numbers. We parse each number separately */
        uint64_t num = 0;
        while (cursor < max) {
            char c = data[cursor];
            if (!is_digit(c))
                break;
            num = num * 10llu + (c - '0');
            if (num > 0xFFFFFFFFu)
                goto fail;
            cursor++;
        }

        char c = to_lower(data[cursor]);
        switch (c) {
        case ' ': case '\t':
        case '(': case ')':
        case '\r': case '\n':
        case ';':
            /* legal white space terminating field */
            break;
        case 'w': /* weeks */
            num *= 7ull * 24ull * 3600ull;
            cursor++;
            break;
        case 'd': /* days */
            num *= 24ull * 3600ull;
            cursor++;
            break;
        case 'h': /* hourse */
            num *= 3600ull;
            cursor++;
            break;
        case 'm': /* minutes */
            num *= 60ull;
            cursor++;
            break;
        case 's': /* seconds */
            num *= 1ull;
            cursor++;
            break;
        default:
            goto fail;
        }

        total += num;
        if (total > 0xFFFFFFFFu)
            goto fail;
    }
    
    *ttl_out = (unsigned)total;
    return cursor;
fail:
    *err = ZONE_ERROR_BAD_TTL;
    return cursor;
}

size_t
zone_atom_ttl(const char *data, size_t cursor, size_t max,
              struct wire_record_t *out) {
    unsigned ttl;
    int err = 0;
    
    /* Step 1: parse the input */
    cursor = parse_ttl_seconds(data, cursor, max, &ttl, &err);
    
    /* Step 2: write the output */
    wire_append_uint32(out, ttl);
    
    if (err)
        goto fail;
    return cursor;
fail:
    return PARSE_ERR(err, cursor, max, out);
}

size_t
parse_ttl_fast(const char *data, size_t cursor, size_t max, unsigned *ttl, int *err) {
    size_t orig_cursor = cursor;
    uint64_t result  = 0;
    int error = 0;
    for (;;) {
        char c = data[cursor];
        if (!is_digit(c))
            break;
        result = result * 10 + c - '0';
        cursor++;
    }
    error |= ((result & 0xFFFFFFFF00000000ull) != 0);
    char c = data[cursor];
    error |= (c != ' ' && c != '\t');
    if (error)
        return parse_ttl_seconds(data, orig_cursor, max, ttl, err);
    *ttl = (unsigned)result;
    return cursor;
}
static  size_t
 (*new_parse_ttl)(const char *data, size_t cursor, size_t max, unsigned *ttl, int *err) = parse_ttl_fast;

#include <string.h>

size_t
new_parse_ttl2x(const char *data, size_t cursor, size_t max, size_t len, unsigned *ttl, int *err) {
    if (len > 8) {
        *err |= 1;
        return cursor;
    }
    uint64_t xxx = 0x3030303030303030;
    memcpy(&xxx, data + cursor + 8 - len, len);
    xxx = (xxx & 0x0F0F0F0F0F0F0F0F) * 2561 >> 8;
    xxx = (xxx & 0x00FF00FF00FF00FF) * 6553601 >> 16;
    xxx = (xxx & 0x0000FFFF0000FFFF) * 42949672960001 >> 32;
    
    *err |= xxx & 0xFFFFFFFF00000000ull;
    *ttl = (unsigned)xxx;
    return cursor + len;
}
size_t
 (*new_parse_ttl2)(const char *data, size_t cursor, size_t max, size_t len, unsigned *ttl, int *err) = new_parse_ttl2x;


#include <sys/time.h>
void zone_atom_ttl_bench(void) {
    struct timeval start, end;
    int err = 0;
    uint64_t total_ttl = 0;
    gettimeofday(&start, NULL);

    size_t i;
    for (i=0; i<100000000; i++) {
        unsigned ttl;
        char buf[] = "3600 ";
        buf[3] = '0' + (i&3);
 
        new_parse_ttl(buf, 0, 5, &ttl, &err);
        total_ttl += ttl;
    }
    gettimeofday(&end, NULL);
    
    if (err)
        printf("***ERROR****\n");
    printf("total %llu\n", total_ttl);
    long total_bytes = i * 5;
    long total_records = i;
    double elapsed = (end.tv_sec - start.tv_sec) +
                    (end.tv_usec - start.tv_usec) / 1000000.0;
    double gbps = (total_bytes / (1024.0 * 1024.0 * 1024.0)) / elapsed;
    
    printf("\nParsed %ld records in %.4f seconds\n", (long)total_records, elapsed);
    printf("Throughput: %.2f GB/s\n", gbps);
    printf("Records/sec: %.0f\n", total_records / elapsed);
   
}
