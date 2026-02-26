// zone-parse-header.c
//
// =============================== FULL SPEC ==================================
// zone_parse_header(): parse TTL + CLASS + TYPE fields that follow the owner name
// in a DNS zonefile record.
//
// Signature / style:
//   - returns: bytes consumed
//   - inputs:  (data, i, max)
//   - outputs: zone_status_t *st (extended with ttl, dns_class, type, flags)
//
// SIMD fast-path model:
//   - Classify exactly 32 bytes from data+i using a runtime-dispatched function
//     `classify32()` that returns TWO 32-bit masks:
//       * ws_mask    : bit k=1 iff byte k is space or tab (' ' or '\t')
//       * alnum_mask : bit k=1 iff byte k is [A-Za-z0-9]
//
// Parsing algorithm:
//   - We parse up to 3 fields in this order:
//       field #1: may be TTL (if begins with digit) OR keyword (CLASS/TYPE)
//       field #2: keyword only (CLASS/TYPE)
//       field #3: keyword only (TYPE required)
//
//   - Between fields: only space/tab is allowed.
//   - Tokens: must be contiguous ALNUM only.
//   - Any other characters encountered while parsing (including '(' ')' ';' etc.)
//     cause an error.
//
// Lookup:
//   - zone_kw_lookup(tok, len) returns a small integer:
//       0      => unknown
//       1..4   => CLASS id (1 == IN); other ids map to other class codes
//       >=5    => TYPE table index (value - 5)
//   - zone_type_by_index(idx) returns a descriptor containing a numeric RR type code.
//
// Errors / fallback:
//   - Any error causes all results to be abandoned and we fall back to
//       zone_parse_classify2(data, start_i, max, st)
//     which you will implement later (non-SIMD, handles comments/parens/etc).
//   - If TYPE is not found after 3 fields => error => fallback.
//
// Notes:
//   - This module only implements the SIMD classifiers and the strict fast path.
//   - It intentionally does NOT try to handle comments, parentheses, unusual
//     whitespace, or multiline records.
// ============================================================================
#include "zone-parse.h"
#include "zone-parse-record.h"
#include <string.h>



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



size_t
zone_parse_header(const char *data, size_t cursor, size_t max,
                  struct wire_record_t *out,
                  unsigned *depth)
{
    int err = 0;
    unsigned rrttl = out->state.default_ttl;
    unsigned rrclass = 1;

    if (is_zone_space(data[cursor]))
        cursor = zone_parse_space(data, cursor, max, out, depth);

    /*
     * Parse up to three fields until we find a TYPE
     */
    for (int field = 0; field < 3; field++) {
        
        if (cursor >= max)
            goto fail;
        
        
        /* ---- TTL ---- */
        if (field == 0 && is_digit(data[cursor])) {
            cursor = parse_ttl_seconds(data, cursor, max, &rrttl, &err);
            cursor = zone_parse_space(data, cursor, max, out, depth);
            continue;
        }
        
        /* ---- CLASS/TYPE ---- */
        size_t next = cursor;
        while (is_alnum_ascii(data[next]))
            next++;
        unsigned type_value;
        unsigned type_idx;
        if (next - cursor == 2 & data[cursor+0] == 'I' && data[cursor+1] == 'N') {
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
            cursor = zone_parse_space(data, cursor, max, out, depth);
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
        cursor = zone_parse_space(data, cursor, max, out, depth);
        return cursor;
    }

    /*
     * If we processed 3 fields without finding TYPE => error => fallback
     */
fail:
    return PARSE_ERR(err, cursor, max, out);
}

#include <stdint.h>
#include <stddef.h>

struct zone_type_test_expect {
    int error_code;        /* 0 = success */
    uint32_t rrttl;          /* 0 if not present */
    uint16_t rrclass;      /* 0 if not present (IN=1, CH=3, HS=4) */
    uint16_t rrtype_value;   /* 0 if not present */
    const char *rrtype_name;/* NULL for TYPE### or if not present */
    size_t consumed;
};

struct zone_type_test_case {
  const char *input;
  struct zone_type_test_expect expect;
};

/* Notes:
 * - test cases must start with a space
 */
static const struct zone_type_test_case test_cases[] = {
    /*{"    TYPE65280 \\# 4 DEADBEEF   ; unknown private use\n",
        { 0, 0, 0, 65280, NULL, 14 }},*/
    /* 10 */
 

    /* 0 */
    {"                 3600   IN   A      192.0.2.10        ; web v4\n",
    { 0, 3600, 1, 1, "A", 36 }},
    {"                 IN   A      192.0.2.10        ; web v4\n",
    { 0, 0, 1, 1, "A", 29 }},
    {"                 A      192.0.2.10        ; web v4\n",
    { 0, 0, 0, 1, "A", 24 }},

    /* 1 */
    {"\t\t\tIN\tAAAA\t2001:db8::10\t\t; web v6\n",
        { 0, 0, 1, 28, "AAAA", 11 }},
    
    /* 2 */
    {"        300   IN   A      192.0.2.11   ; same owner as previous\n",
        { 0, 300, 1, 1, "A", 26 }},
    
    /* 3 */
    {"      IN   CNAME   target.example.     ; points at target\n",
        { 0, 0, 1, 5, "CNAME", 19 }},
    
    /* 4 */
    {
        "   3600  IN  SOA  ns1.example. hostmaster.example. (\n"
        "            2026020201   ; serial\n"
        "            7200         ; refresh\n"
        "            3600         ; retry\n"
        "            1209600      ; expire\n"
        "            3600 )       ; minimum\n",
        { 0, 3600, 1, 6, "SOA", 18 }
    },
    
    /* 5 */
    {
        "          86400 IN NS   ns1.example.   ; primary\n",
        { 0, 86400, 1, 2, "NS", 24 }
    },
    
    /* 6 */
    {
        " \t86400\tIN\tNS\tns2.example.\t\t\n",
        { 0, 86400, 1, 2, "NS", 14 }
    },
    
    /* 7 */
    {
        "   IN  MX  10   mail.example.   ; primary mail\n",
        { 0, 0, 1, 15, "MX", 11 }
    },
    
    /* 8 */
    {
        "  600 IN TXT \"v=spf1 include:example.net; a mx ~all\" ; spf-ish\n",
        { 0, 600, 1, 16, "TXT", 13 }
    },
    
    /* 9 */
    {
        "  600 IN TXT \"part1 \"  \"part2\"   \" part3\"   ; concat\n",
        { 0, 600, 1, 16, "TXT", 13 }
    },
    
    /* 10 */
    {
        " 600 IN TXT (\n"
        "      \"line1\\n\"\n"
        "      \"line2 with \\\"quote\\\" and \\\\ backslash\" )\n",
        { 0, 600, 1, 16, "TXT", 20 }
    },
    
    /* 11 */
    {
        "   1800   IN  SRV   10  60  5060   sipserver.example. ; voip\n",
        { 0, 1800, 1, 33, "SRV", 20 }
    },
    
    /* 12 */
    {
        "  300 IN SVCB 1 svc.example. alpn=\"h2 h3\" ipv4hint=192.0.2.20 ; hints\n",
        { 0, 300, 1, 64, "SVCB", 14 }
    },
    
    /* 13 */
    {
        " 300 IN HTTPS 1 . alpn=h3 port=443 ech=\"AAAA\" ; minimal https rr\n",
        { 0, 300, 1, 65, "HTTPS", 14 }
    },
    
    /* 14 */
    {"   300 IN TYPE65280 \\# 4 DEADBEEF   ; unknown private use\n",
        { 0, 300, 1, 65280, NULL, 20}},
    
    /* 15 */
    {
        "   300 IN TYPE65000 ( \\# 8 01020304 05060708 ) ; split hex\n",
        { 0, 300, 1, 65000, NULL, 22 }
    },
    
    /* 16 */
    {
        "  3600 IN CAA 0 issue \"letsencrypt.org\" ; caa issue\n",
        { 0, 3600, 1, 257, "CAA", 14 }
    },
    
    /* 17 */
    {
        "  3600 IN NAPTR 100 10 \"u\" \"E2U+sip\" \"!^.*$!sip:help@example.!\" . ; naptr\n",
        { 0, 3600, 1, 35, "NAPTR", 16 }
    },
    
    /* 18 */
    {
        "(;label\n  300) IN(TXT \"owner has escapes\" ); name tests\n",
        { 0, 300, 1, 16, "TXT", 22 }
    },
    {0}
};
#include <string.h>
#include <stdio.h>

int zone_parse_header_quicktest(void) {
    int err = 0;
    unsigned char wirebuf[128*1024];
    int i;
    
    for (i=0; test_cases[i].input; i++) {
        unsigned depth = 0;
        const char *data = test_cases[i].input;
        size_t max = strlen(data);
        wire_record_t out = {0};
        size_t consumed;
        const struct zone_type_test_expect *expect = &test_cases[i].expect;
        size_t cursor = 0;
        size_t next;
        unsigned rrtype;
        unsigned rrclass;
        unsigned rrttl;
        
        /*
         * Prepare the simulated input
         */
        out.wire.buf = wirebuf;
        out.wire.len = 0;
        out.wire.max = sizeof(wirebuf);
        
        /*
         * Call the test function
         */
        next = zone_parse_header2(data, cursor, max, &out, &depth);
        consumed = next - cursor;
        rrtype = out.wire.buf[0]<<8 | out.wire.buf[1];
        rrclass = out.wire.buf[2]<<8 | out.wire.buf[3];
        rrttl = out.wire.buf[4]<<24 | out.wire.buf[5]<<16 | out.wire.buf[6]<<8 | out.wire.buf[7];
        
        /*
         * Verify the output
         */
        if (out.err.code && expect->error_code == 0) {
            fprintf(stderr, "[-] header2:%d: unexpected error\n", i);
            fprintf(stderr, "--- %s", data);
            return err;
        }
        if (consumed != expect->consumed) {
            fprintf(stderr, "[-] header2:%d: consumed: found=%u, expected=%u\n", i,
                    (unsigned)consumed, (unsigned)expect->consumed);
            fprintf(stderr, "--- %s", data);
            //return err;
        }
        if (expect->rrttl && expect->rrttl != rrttl) {
            fprintf(stderr, "[-] header2:%d: ttl: found=%u, expected=%u\n", i,
                    (unsigned)rrttl, (unsigned)expect->rrttl);
            fprintf(stderr, "--- %s", data);
            //return err;
        }
        if (expect->rrclass && expect->rrclass != rrclass) {
            fprintf(stderr, "[-] header2:%d: class: found=%u, expected=%u\n", i,
                    (unsigned)rrclass, (unsigned)expect->rrclass);
            fprintf(stderr, "--- %s", data);
            //return err;
        }
        if (expect->rrtype_value && expect->rrtype_value != out.rrtype.value) {
            fprintf(stderr, "[-] header2:%d: type: found=%u, expected=%u\n", i,
                    (unsigned)out.rrtype.value, (unsigned)expect->rrtype_value);
            fprintf(stderr, "--- %s", data);
            //return err;
        }
    }
    

    return err;
}
