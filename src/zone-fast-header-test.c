/* zone-fast-header-test.c
 *
 * Quicktest for:
 *   size_t zone_fast_header(const char *data, size_t cursor, size_t max,
 *                           struct wire_record_t *out,
 *                           unsigned *depth);
 *
 * This validates:
 *   - out->name_length
 *   - rrtype  from out->wire.buf[out->name_length + 0..1]
 *   - rrclass from out->wire.buf[out->name_length + 2..3]
 *   - rrttl   from out->wire.buf[out->name_length + 4..7]
 *   - returned cursor
 *   - final depth
 *
 * It does not validate the actual encoded owner name bytes, only name_length.
 *
 * The test harness also preprocesses the input using:
 *   zone_fast_classify(data, length, whitespace, intoken)
 *
 * Assumptions:
 *   - omitted class defaults to IN
 *   - omitted ttl defaults to out->state.default_ttl
 *   - header fields must appear in order:
 *         owner [ttl] [class] type
 *   - depth is only 0 or 1 in these tests
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "zone-parse.h"
#include "zone-fast-header.h"
#include "zone-fast-classify.h"

enum {
    RR_A      = 1,
    RR_NS     = 2,
    RR_CNAME  = 5,
    RR_SOA    = 6,
    RR_PTR    = 12,
    RR_MX     = 15,
    RR_TXT    = 16,
    RR_AAAA   = 28,
    RR_SRV    = 33,
    RR_NAPTR  = 35,
    RR_DS     = 43,
    RR_SSHFP  = 44,
    RR_RRSIG  = 46,
    RR_NSEC   = 47,
    RR_DNSKEY = 48,
    RR_TLSA   = 52,
    RR_SPF    = 99,
    RR_URI    = 256,
    RR_CAA    = 257,
    RR_SVCB   = 64,
    RR_HTTPS  = 65
};

enum {
    CLASS_IN = 1,
    CLASS_CH = 3,
    CLASS_HS = 4
};

typedef struct header_testcase_t {
    const char *desc;
    const char *record;
    size_t expected_cursor;
    size_t expected_name_length;
    unsigned expected_type;
    unsigned expected_class;
    unsigned expected_ttl;
    unsigned initial_depth;
    unsigned expected_depth;
} header_testcase_t;

static uint16_t
read_u16be(const unsigned char *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static uint32_t
read_u32be(const unsigned char *p)
{
    return ((uint32_t)p[0] << 24)
         | ((uint32_t)p[1] << 16)
         | ((uint32_t)p[2] << 8)
         | ((uint32_t)p[3] << 0);
}

static void
reset_out(wire_record_t *out,
          unsigned char *wirebuf,
          size_t wiremax,
          uint64_t *whitespace,
          uint64_t *intoken)
{
    static const unsigned char origin[13] = {
        7, 'e','x','a','m','p','l','e',
        3, 'c','o','m',
        0
    };

    memset(out, 0, sizeof(*out));
    out->wire.buf = wirebuf;
    out->wire.len = 0;
    out->wire.max = wiremax;
    out->state.origin = origin;
    out->state.origin_length = 13;
    out->state.default_ttl = 42;
    out->whitespace = whitespace;
    out->intoken = intoken;
}

static void print_name(const wire_record_t *out) {
    size_t i = 0;
    const unsigned char *buf = out->wire.buf;
    while (i < out->ownername_length) {
        unsigned len = buf[i++];
        printf("%.*s.", len, buf);
        i += len;
    }
}

static int
run_one_test(const header_testcase_t *tc, int index, wire_record_t *out)
{
    unsigned char wirebuf[1024];
    uint64_t whitespace[16];
    uint64_t intoken[16];
    size_t length;
    size_t cursor;
    unsigned depth;
    unsigned got_type;
    unsigned got_class;
    unsigned got_ttl;
    int failed;

    length = strlen(tc->record);

    memset(wirebuf, 0xA5, sizeof(wirebuf));
    memset(whitespace, 0, sizeof(whitespace));
    memset(intoken, 0, sizeof(intoken));

    reset_out(out, wirebuf, sizeof(wirebuf), whitespace, intoken);

    zone_fast_classify(tc->record, length, whitespace, intoken);

    depth = tc->initial_depth;
    cursor = zone_fast_header(tc->record, 0, length, out, &depth);

    failed = 0;

    if (out->ownername_length != tc->expected_name_length) {
        printf("zone_fast_header test %d (%s): name_length mismatch\n", index, tc->desc);
        printf("  record:    \"%s\"\n", tc->record);
        printf("  expected:  %lu\n", (unsigned long)tc->expected_name_length);
        printf("  got:       %lu\n", (unsigned long)out->ownername_length);
        printf("  name:      ");
        print_name(out);
        failed = 1;
    }

    if (out->wire.len < out->ownername_length + 8) {
        printf("zone_fast_header test %d (%s): wire.len too short\n", index, tc->desc);
        printf("  record:    \"%s\"\n", tc->record);
        printf("  wire.len:  %lu\n", (unsigned long)out->wire.len);
        printf("  need:      %lu\n", (unsigned long)(out->ownername_length + 8));
        return 1;
    }

    got_type  = read_u16be(out->wire.buf + out->ownername_length + 0);
    got_class = read_u16be(out->wire.buf + out->ownername_length + 2);
    got_ttl   = read_u32be(out->wire.buf + out->ownername_length + 4);

    if (got_type != tc->expected_type) {
        printf("zone_fast_header test %d (%s): rrtype mismatch\n", index, tc->desc);
        printf("  record:    \"%s\"\n", tc->record);
        printf("  expected:  %u\n", tc->expected_type);
        printf("  got:       %u\n", got_type);
        failed = 1;
    }

    if (got_class != tc->expected_class) {
        printf("zone_fast_header test %d (%s): rrclass mismatch\n", index, tc->desc);
        printf("  record:    \"%s\"\n", tc->record);
        printf("  expected:  %u\n", tc->expected_class);
        printf("  got:       %u\n", got_class);
        failed = 1;
    }

    if (got_ttl != tc->expected_ttl) {
        printf("zone_fast_header test %d (%s): rrttl mismatch\n", index, tc->desc);
        printf("  record:    \"%s\"\n", tc->record);
        printf("  expected:  %u\n", tc->expected_ttl);
        printf("  got:       %u\n", got_ttl);
        failed = 1;
    }

    if (cursor != tc->expected_cursor) {
        printf("zone_fast_header test %d (%s): cursor mismatch\n", index, tc->desc);
        printf("  record:    \"%s\"\n", tc->record);
        printf("  expected:  %lu\n", (unsigned long)tc->expected_cursor);
        printf("  got:       %lu\n", (unsigned long)cursor);
        failed = 1;
    }

    if (depth != tc->expected_depth) {
        printf("zone_fast_header test %d (%s): depth mismatch\n", index, tc->desc);
        printf("  record:    \"%s\"\n", tc->record);
        printf("  initial:   %u\n", tc->initial_depth);
        printf("  expected:  %u\n", tc->expected_depth);
        printf("  got:       %u\n", depth);
        failed = 1;
    }

    if (out->err.code != 0) {
        printf("zone_fast_header test %d (%s): unexpected err.code\n", index, tc->desc);
        printf("  record:    \"%s\"\n", tc->record);
        printf("  err.code:  %d\n", out->err.code);
        printf("  err.cursor:%lu\n", (unsigned long)out->err.cursor);
        failed = 1;
    }

    return failed;
}

int
zone_fast_header_quicktest(int backend)
{
    static const header_testcase_t tests[] = {
        { "comment after type",                                     "www 300 IN A ; comment\n1.2.3.4",                            22, 17, RR_A,     CLASS_IN, 300,        0, 0 },
        
        
        
        { "root owner absolute",                                    ". 300 IN NS ns1.example.com.",                               12, 1,  RR_NS,    CLASS_IN, 300,        0, 0 },
        { "at owner ttl class type",                                "@ 300 IN A 1.2.3.4",                                         11, 13, RR_A,     CLASS_IN, 300,        0, 0 },
        { "basic relative owner ttl class type",                    "www 300 IN A 1.2.3.4",                                      13, 17, RR_A,     CLASS_IN, 300,        0, 0 },
        { "basic relative owner omitted ttl",                       "www IN A 1.2.3.4",                                           9,  17, RR_A,     CLASS_IN, 42,         0, 0 },
        { "basic relative owner omitted class",                     "www 300 A 1.2.3.4",                                          10, 17, RR_A,     CLASS_IN, 300,        0, 0 },
        { "basic relative owner omitted ttl and class",             "www A 1.2.3.4",                                              6,  17, RR_A,     CLASS_IN, 42,         0, 0 },
        { "at owner ttl class type",                                "@ 300 IN A 1.2.3.4",                                         11, 13, RR_A,     CLASS_IN, 300,        0, 0 },
        { "at owner omitted ttl class",                             "@ A 1.2.3.4",                                                4,  13, RR_A,     CLASS_IN, 42,         0, 0 },
        { "absolute owner",                                         "www.example.net. 300 IN A 1.2.3.4",                          26, 17, RR_A,     CLASS_IN, 300,        0, 0 },
        { "two label relative owner",                               "a.b 15 IN NS ns1.example.com.",                              13, 17, RR_NS,    CLASS_IN, 15,         0, 0 },
        { "multi label relative owner",                             "x.y.z 86400 IN MX 10 mail.example.com.",                     18, 19, RR_MX,    CLASS_IN, 86400,      0, 0 },

        { "ttl zero",                                               "zero 0 IN A 0.0.0.0",                                        12, 18, RR_A,     CLASS_IN, 0,          0, 0 },
        { "ttl max",                                                "max 4294967295 IN A 255.255.255.255",                        20, 17, RR_A,     CLASS_IN, 4294967295u,0, 0 },
        { "class CH",                                               "chaos 60 CH TXT \"version.bind\"",                           16, 19, RR_TXT,   CLASS_CH, 60,         0, 0 },
        { "class HS",                                               "chaos 60 HS TXT \"version.bind\"",                           16, 19, RR_TXT,   CLASS_HS, 60,         0, 0 },
        { "omitted class defaults IN for TXT",                      "txt 123 TXT \"hello\"",                                      12, 17, RR_TXT,   CLASS_IN, 123,        0, 0 },
        { "omitted ttl and class defaults",                         "txt TXT \"hello\"",                                          8,  17, RR_TXT,   CLASS_IN, 42,         0, 0 },

        { "AAAA",                                                   "ipv6 3600 IN AAAA 2001:db8::1",                              18, 18, RR_AAAA,  CLASS_IN, 3600,       0, 0 },
        { "CNAME",                                                  "alias 7200 IN CNAME target.example.com.",                    20, 19, RR_CNAME, CLASS_IN, 7200,       0, 0 },
        { "MX",                                                     "mail 600 IN MX 10 mx.example.com.",                          15, 18, RR_MX,    CLASS_IN, 600,        0, 0 },
        { "TXT",                                                    "txt 123 IN TXT \"hello\"",                                   15, 17, RR_TXT,   CLASS_IN, 123,        0, 0 },
        { "SPF",                                                    "spf 900 IN SPF \"v=spf1 -all\"",                             15, 17, RR_SPF,   CLASS_IN, 900,        0, 0 },
        { "SRV",                                                    "_sip._tcp 86400 IN SRV 10 20 443 target.example.com.",      23, 23, RR_SRV,   CLASS_IN, 86400,      0, 0 },
        { "SSHFP",                                                  "ssh 1200 IN SSHFP 1 1 deadbeef",                             18, 17, RR_SSHFP, CLASS_IN, 1200,       0, 0 },
        { "TLSA",                                                   "_443._tcp 600 IN TLSA 3 1 1 deadbeef",                       22, 23, RR_TLSA,  CLASS_IN, 600,        0, 0 },
        { "CAA",                                                    "caa 300 IN CAA 0 issue \"letsencrypt.org\"",                 15, 17, RR_CAA,   CLASS_IN, 300,        0, 0 },
        { "HTTPS",                                                  "svc 1800 IN HTTPS 1 . alpn=\"h2,h3\"",                       18, 17, RR_HTTPS, CLASS_IN, 1800,       0, 0 },
        { "SVCB",                                                   "svc 1800 IN SVCB 1 svc.example.com.",                        17, 17, RR_SVCB,  CLASS_IN, 1800,       0, 0 },
        { "URI",                                                    "uri 60 IN URI 10 1 \"https://example.com/\"",               14, 17, RR_URI,   CLASS_IN, 60,         0, 0 },
        { "PTR",                                                    "1 PTR host.example.com.",                                    6,  15, RR_PTR,   CLASS_IN, 42,          0, 0 },
        { "SOA",                                                    "@ 3600 IN SOA ns1.example.com. hostmaster.example.com. 1 2 3 4 5", 14, 13, RR_SOA, CLASS_IN, 3600, 0, 0 },
        { "NAPTR",                                                  "nap 300 IN NAPTR 100 50 \"s\" \"SIP+D2U\" \"\" _sip._udp.example.com.", 17, 17, RR_NAPTR, CLASS_IN, 300, 0, 0 },
        { "DS",                                                     "ds 300 IN DS 12345 13 2 deadbeef",                           13, 16, RR_DS,    CLASS_IN, 300,        0, 0 },
        { "DNSKEY",                                                 "key 300 IN DNSKEY 257 3 13 deadbeef",                        18, 17, RR_DNSKEY,CLASS_IN, 300,        0, 0 },
        { "RRSIG",                                                  "sig 300 IN RRSIG A 13 3 300 20250101000000 20240101000000 12345 example.com. deadbeef", 17, 17, RR_RRSIG, CLASS_IN, 300, 0, 0 },
        { "NSEC",                                                   "nsec 300 IN NSEC next.example.com. A NS SOA MX RRSIG NSEC DNSKEY", 17, 18, RR_NSEC, CLASS_IN, 300, 0, 0 },

        { "generic type",                                           "x 42 IN TYPE65280 \\# 0",                                    18, 15, 65280u,   CLASS_IN, 42,         0, 0 },
        { "generic type omitted class",                             "x 42 TYPE65280 \\# 0",                                       15, 15, 65280u,   CLASS_IN, 42,         0, 0 },
        { "generic type omitted ttl and class",                     "x TYPE65280 \\# 0",                                          12, 15, 65280u,   CLASS_IN, 42,         0, 0 },

        { "tab separators",                                         "www\t300\tIN\tA\t1.2.3.4",                                   13, 17, RR_A,     CLASS_IN, 300,        0, 0 },
        { "many spaces",                                            "www   300   IN   A     1.2.3.4",                             23, 17, RR_A,     CLASS_IN, 300,        0, 0 },
        { "leading tabs nowhere cursor 0",                          "www IN A\t1.2.3.4",                                          9,  17, RR_A,     CLASS_IN, 42,         0, 0 },
        { "LF after type",                                          "www 300 IN A\n1.2.3.4",                                      12, 17, RR_A,     CLASS_IN, 300,        0, 0 },
        { "CRLF after type",                                        "www 300 IN A\r\n1.2.3.4",                                    12, 17, RR_A,     CLASS_IN, 300,        0, 0 },
        { "space tab after type",                                   "www 300 IN A \t\t1.2.3.4",                                   15, 17, RR_A,     CLASS_IN, 300,        0, 0 },

        { "comment after type",                                     "www 300 IN A ; comment\n1.2.3.4",                            22, 17, RR_A,     CLASS_IN, 300,        0, 0 },
        { "comment after type with tabs",                           "www 300 IN A\t; comment\n1.2.3.4",                           22, 17, RR_A,     CLASS_IN, 300,        0, 0 },
        { "comment after omitted ttl/class",                        "www A ; x\n1.2.3.4",                                         9, 17, RR_A,     CLASS_IN, 42,         0, 0 },

        { "open paren separated after type",                        "www 300 IN A ( 1.2.3.4",                                     15, 17, RR_A,     CLASS_IN, 300,        0, 1 },
        { "open paren attached to type",                            "www 300 IN A( 1.2.3.4",                                      14, 17, RR_A,     CLASS_IN, 300,        0, 1 },
        { "open paren attached no following space",                 "www 300 IN A(1.2.3.4",                                       13, 17, RR_A,     CLASS_IN, 300,        0, 1 },
        { "open paren after omitted ttl/class",                     "www A(1.2.3.4",                                              6,  17, RR_A,     CLASS_IN, 42,         0, 1 },
        { "open paren separated omitted ttl/class",                 "www A ( 1.2.3.4",                                            8,  17, RR_A,     CLASS_IN, 42,         0, 1 },

        { "open close parens separated",                            "www 300 IN A ( ) 1.2.3.4",                                   17, 17, RR_A,     CLASS_IN, 300,        0, 0 },
        { "open close parens attached",                             "www 300 IN A() 1.2.3.4",                                     15, 17, RR_A,     CLASS_IN, 300,        0, 0 },
        { "open attached close separated",                          "www 300 IN A( ) 1.2.3.4",                                    16, 17, RR_A,     CLASS_IN, 300,        0, 0 },
        { "open separated close attached",                          "www 300 IN A ()1.2.3.4",                                     15, 17, RR_A,     CLASS_IN, 300,        0, 0 },
        { "open close parens with tabs",                            "www 300 IN A\t(\t)\t1.2.3.4",                                17, 17, RR_A,     CLASS_IN, 300,        0, 0 },

        { "comment inside paren open only",                         "www 300 IN A ( ; hi\n1.2.3.4",                               20, 17, RR_A,     CLASS_IN, 300,        0, 1 },
        { "comment between open and close",                         "www 300 IN A ( ; hi\n ) 1.2.3.4",                            23, 17, RR_A,     CLASS_IN, 300,        0, 0 },
        { "type followed by open paren and LF",                     "www 300 IN A(\n1.2.3.4",                                     14, 17, RR_A,     CLASS_IN, 300,        0, 1 },
        { "type followed by open close and LF",                     "www 300 IN A()\n1.2.3.4",                                    14, 17, RR_A,     CLASS_IN, 300,        0, 0 },

        { "initial depth 1 no parens stays 1",                      "www 300 IN A 1.2.3.4",                                       13, 17, RR_A,     CLASS_IN, 300,        1, 1 },

        { "root owner absolute",                                    ". 300 IN NS ns1.example.com.",                               12, 1,  RR_NS,    CLASS_IN, 300,        0, 0 },
        { "single char owner",                                      "x 300 IN A 1.2.3.4",                                         11, 15, RR_A,     CLASS_IN, 300,        0, 0 },
        { "owner with digits and hyphen",                           "host-1 900 IN SPF \"v=spf1 -all\"",                          18, 20, RR_SPF,   CLASS_IN, 900,        0, 0 },
        { "service owner underscore",                               "_443._tcp 600 IN TLSA 3 1 1 deadbeef",                       22, 23, RR_TLSA,  CLASS_IN, 600,        0, 0 },
        { 0, 0, 0, 0, 0, 0, 0, 0, 0 }
    };

    wire_record_t out;
    int failures;
    int i;

    zone_fast_header_init(backend);

    failures = 0;
    for (i = 0; tests[i].desc != 0; i++) {
        failures += run_one_test(&tests[i], i + 1, &out);
    }

    if (failures) {
        printf("zone_fast_header_quicktest: %d test(s) failed\n", failures);
        return 1;
    }

    return 0;
}
