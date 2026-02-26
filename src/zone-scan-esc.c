#include "zone-scan.h"
#include <string.h>
#include <stdio.h>
#include <assert.h>

static inline int is_hex(int c) {
    if ('0' <= c && c <= '9')
        return 1;
    if ('a' <= c && c <= 'f')
        return 1;
    if ('A' <= c && c <= 'F')
        return 1;
    return 0;
}

static inline int is_octal(int c) {
    if ('0' <= c && c <= '7')
        return 1;
    return 0;
}

// Handle backslash escapes: \DDD (octal), \<newline> (line continuation), or \X (escape char)
size_t zone_scan_escape(const char *data, size_t offset, size_t max) {
    
    
    /* Skip the backslash */
    assert(data[offset] == '\\');
    offset++;

    if (offset >= max)
        return max + 1;

    /* Check for octal escape: \DDD */
    if (is_octal(data[offset])) {
        offset++;
        if (offset >= max)
            return max + 1;
        else if (is_octal(data[offset])) {
            offset++;
            if (offset >= max)
                return max + 1;
            else if (is_octal(data[offset])) {
                offset++;
            }
        }
        return offset;
    }
    
    /* Check for hex escape: \xDD */
    if (data[offset] == 'x' || data[offset] == 'X') {
        offset++;
        if (offset >= max)
            return max + 1;
        else if (is_hex(data[offset])) {
            offset++;
            if (offset >= max)
                return max + 1;
            else if (is_hex(data[offset])) {
                offset++;
                if (offset >= max)
                    return max + 1;
            }
        }
        return offset;
    }
    
    /* Can't escape newlines.
     * FEATURE: if we add escapeing of newlines, then we need
     * to handle both \r\n CRLF and \n LF variants */
    if (data[offset] == '\n' || data[offset] == '\r') {
        return max + 1;
    }
    
    /* Regular escape: \X
     * Skip \ and next char */
    return offset + 1;
}


int zone_scan_escape_quicktest(void) {
    static struct testcases {
        const char *data;
        size_t expected;
    } tests[] = {
        {"\\12", 4}, /* error: input too small to resolve */
        {"\\123", 4},
        {"\\123 ", 4},
        {"\\1234", 4},
        {"\\12xx", 3},
        {"\\1xx", 2},
        {"\\xxx", 2},
        {"\\1", 3},
        {"\\\n", 3},
        {"\\\r", 3},
        {"\\\nxyz", 6},
        {"\\", 2},
        {"\\x", 3},
        {"\\xa", 4},
        {"\\xab", 5},
        {"\\xabc", 4},
        {0,0}
    };
    
    int err = 0;
    
    for (int i=0; tests[i].data; i++) {
        char buf[1024];
        size_t in_len = strlen(tests[i].data);
        memset(buf, '\n', sizeof(buf));
        memcpy(buf, tests[i].data, in_len);
        
        size_t out = zone_scan_escape(buf, 0, in_len);
        if (out != tests[i].expected) {
            fprintf(stderr, "[-] scan.esc(): test %d failed: \"%s\"\n", i, tests[i].data);
            err++;
        }
    }
    
    return err;
}
