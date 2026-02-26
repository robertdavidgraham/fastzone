#include "zone-scan.h"
#include "zone-qbench.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>

#include <stddef.h>

struct zone_roundtrip_test {
    const char *in;
    const char *out;
};

#if 0
static const struct zone_roundtrip_test zone_roundtrip_tests[] = {
    /* --- Basic whitespace normalization --- */
    {
        "www 3600 IN A 192.0.2.1\n",
        "www 3600 IN A 192.0.2.1\n",
    },
    {
        "www\t3600\tIN\tA\t192.0.2.1\n",
        "www 3600 IN A 192.0.2.1\n",
    },
    {
        "www    3600   IN   A    192.0.2.1   \n",
        "www 3600 IN A 192.0.2.1\n",
    },
    {
        "www 3600 IN A 192.0.2.1 ; trailing comment\n",
        "www 3600 IN A 192.0.2.1\n",
    },
    {
        "www 3600 IN A 192.0.2.1\t; comment after tab\n",
        "www 3600 IN A 192.0.2.1\n",
    },

    /* --- Parentheses: earliest legal placements --- */

    /* ( as first non-ws char */
    {
        "( www 3600 IN A 192.0.2.1 )\n",
        "www 3600 IN A 192.0.2.1\n",
    },

    /* ( immediately after owner */
    {
        "www ( 3600 IN A 192.0.2.1 )\n",
        "www 3600 IN A 192.0.2.1\n",
    },

    /* ( after TTL */
    {
        "www 3600 ( IN A 192.0.2.1 )\n",
        "www 3600 IN A 192.0.2.1\n",
    },

    /* ( after CLASS */
    {
        "www 3600 IN ( A 192.0.2.1 )\n",
        "www 3600 IN A 192.0.2.1\n",
    },

    /* ( after TYPE */
    {
        "www 3600 IN A ( 192.0.2.1 )\n",
        "www 3600 IN A 192.0.2.1\n",
    },

    /* --- Multiline flattening inside parentheses --- */
    {
        "www 3600 IN A (\n"
        "  192.0.2.1\n"
        ")\n",
        "www 3600 IN A 192.0.2.1\n",
    },
    {
        "www 3600 IN MX (\n"
        "  10 mail.example.\n"
        ")\n",
        "www 3600 IN MX 10 mail.example.\n",
    },
    {
        "( www 3600 IN MX\n"
        "  10 mail.example.\n"
        ")\n",
        "www 3600 IN MX 10 mail.example.\n",
    },

    /* --- Comments + parentheses interaction (comments removed) --- */
    {
        "www 3600 IN MX ( 10 mail.example. ) ; comment\n",
        "www 3600 IN MX 10 mail.example.\n",
    },
    {
        "www 3600 IN MX ( 10 mail.example. ; inline comment\n"
        ")\n",
        "www 3600 IN MX 10 mail.example.\n",
    },

    /* --- Nested parentheses (should still flatten correctly) --- */
    {
        "www 3600 IN TXT ( ( \"hello\" ) )\n",
        "www 3600 IN TXT \"hello\"\n",
    },
    {
        "www 3600 IN TXT (\n"
        " ( \"a\" )\n"
        " ( \"b\" )\n"
        ")\n",
        "www 3600 IN TXT \"a\" \"b\"\n",
    },

    /* --- Quoted strings: spaces and semicolons inside quotes must be preserved --- */
    {
        "www 3600 IN TXT \"hello world\"\n",
        "www 3600 IN TXT \"hello world\"\n",
    },
    {
        "www 3600 IN TXT \"semi;colon is not a comment\"\n",
        "www 3600 IN TXT \"semi;colon is not a comment\"\n",
    },
    {
        "www 3600 IN TXT (\n"
        " \"line one\" ; comment removed\n"
        " \"line two\"\n"
        ")\n",
        "www 3600 IN TXT \"line one\" \"line two\"\n",
    },

    /* --- Escapes in quoted strings (zonefile-level): keep as escapes on output --- */
    /* backslash-quote inside quotes */
    {
        "www 3600 IN TXT \"he said \\\"hi\\\"\"\n",
        "www 3600 IN TXT \"he said \\\"hi\\\"\"\n",
    },
    /* backslash-semicolon inside quotes (still literal ';') */
    {
        "www 3600 IN TXT \"a\\;b\"\n",
        "www 3600 IN TXT \"a\\;b\"\n",
    },

    /* --- Other RR types with simple, canonical formatting --- */
    {
        "www 3600 IN AAAA 2001:db8::1\n",
        "www 3600 IN AAAA 2001:db8::1\n",
    },
    {
        "www 3600 IN NS ns1.example.\n",
        "www 3600 IN NS ns1.example.\n",
    },
    {
        "_sip._tcp 3600 IN SRV 10 60 5060 sip.example.\n",
        "_sip._tcp 3600 IN SRV 10 60 5060 sip.example.\n",
    },
    {
        "www 3600 IN CAA 0 issue \"letsencrypt.org\"\n",
        "www 3600 IN CAA 0 issue \"letsencrypt.org\"\n",
    },

    /* --- “Weird” spacing around parentheses and tokens --- */
    {
        "www(3600)IN(A)(192.0.2.1)\n",
        "www 3600 IN A 192.0.2.1\n",
    },
    {
        "www 3600 IN TXT(\"tight\")\n",
        "www 3600 IN TXT \"tight\"\n",
    },
    
    {0,0}
};

static const size_t zone_roundtrip_tests_count =
    sizeof(zone_roundtrip_tests) / sizeof(zone_roundtrip_tests[0]);
#endif
static const char *zonefile =
"$ORIGIN example.com.\n"
"$TTL 3600\n"
"; Typical small-zone skeleton, but with parser-tricky bits sprinkled in\n"
"; - owner-name continuation (blank/leading spaces)\n"
"; - @ shorthand, $ORIGIN, $TTL\n"
"; - mixed presence of TTL/CLASS\n"
"; - multiline records with parentheses\n"
"; - quoted strings + escapes (\\, \\\"), and semicolons inside quotes\n"
"; - escaped spaces / \"odd\" owner names\n"
"; - relative vs absolute names\n"
"\n"
"@               IN  SOA ns1.example.com. hostmaster.example.com. (\n"
"                2026012901 ; serial\n"
"                7200       ; refresh\n"
"                3600       ; retry\n"
"                1209600    ; expire\n"
"                300        ; negative cache\n"
"                )\n"
"\n"
"; NS at apex (explicit TTL+CLASS, and then continuation-owner lines)\n"
"@           86400  IN  NS  ns1.example.com.\n"
"            86400  IN  NS  ns2.example.com.\n"
"\n"
"; Glue-ish A/AAAA for nameservers (owner name once, then continued)\n"
"ns1             IN  A      192.0.2.53\n"
"                IN  AAAA   2001:db8::53\n"
"ns2          300 IN  A      192.0.2.54\n"
"             300 IN  AAAA   2001:db8::54\n"
"\n"
"; Apex records with a mix of TTL+CLASS orderings\n"
"@               A      192.0.2.10\n"
"@           IN  AAAA   2001:db8::10\n"
"@           600 MX 10  mail.example.com.\n"
"@               MX 20  mail2.example.com.\n"
"\n"
"; A couple of hosts; note owner continuation and varied whitespace\n"
"www             300 IN  A      192.0.2.20\n"
"                300 IN  AAAA   2001:db8::20\n"
"api                 IN  CNAME  www\n"
"\n"
"; TXT with tricky content: semicolons, quotes, backslashes, and escaped spaces\n"
"@           1800 IN  TXT \"v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::/32 include:_spf.example.net -all\"\n"
"_dmarc          IN  TXT \"v=DMARC1; p=none; rua=mailto:dmarc-reports@example.com; fo=1\"\n"
"selector1._domainkey  IN TXT (\n"
"                \"v=DKIM1; k=rsa; \"\n"
"                \"p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\" ; comment after a quoted chunk\n"
"                \"MIIBCgKCAQEAtest\\\\+\\\\/\\\\=\\\"with\\\"quotes\" x     \n"
"                )\n"
"\n"
"; SRV with parentheses and continuation; also mixes TTL/CLASS presence\n"
"_sip._tcp       3600 IN  SRV ( 10 60 5060 sip1.example.com.\n"
"                              20 20 5060 sip2.example.com. )\n"
"\n"
"; Relative target (no trailing dot) vs absolute target (with dot)\n"
"mail                IN  A      192.0.2.30\n"
"mail2               IN  A      192.0.2.31\n"
"autodiscover        IN  CNAME  mail\n"
"imap                IN  CNAME  mail.example.com.\n"
"\n"
"; Wildcard\n"
"*.dev           120 IN  A      192.0.2.40\n"
"\n"
"; \"Odd\" owner names that require escapes/quoting in presentation form\n"
"; A label containing an escaped space (\\ )\n"
"host\\ name        IN  A      192.0.2.77\n"
"; A label containing an escaped semicolon (\\;) so it isn't a comment\n"
"semi\\;colon       IN  A      192.0.2.78\n"
"; A label containing an escaped leading at-sign-like text (just to be annoying)\n"
"at\\@label         IN  A      192.0.2.79\n"
"\n"
"; A record with an owner that *looks* absolute already, and one truly absolute\n"
"sub.example.com.    IN  A      192.0.2.88\n"
"absolute.other.net. 900 IN A    198.51.100.9\n"
"\n"
"; A domain-name-ish RDATA with an escaped dot in a label (presentation trick)\n"
"; This is intentionally weird: \"dot\\.label\" means the label contains a literal '.' in presentation\n"
"; Many parsers trip here if they treat it as a separator.\n"
"dot\\.label         IN  TXT \"label contains a literal period: dot\\\\.label\"\n"
"\n"
"; NAPTR with lots of quoting/escapes\n"
"_sip._udp       3600 IN  NAPTR 100 10 \"u\" \"E2U+sip\" \"!^.*$!sip:info@example.com!\" .\n"
"\n"
"; LOC-ish multiline (just to exercise parentheses parsing in generic way)\n"
"office              IN  TXT (\n"
"                \"123 Example St, Suite 500\" \n"
"                \"New York, NY\" )\n"
"\n"
"; End of zone\n"
;

static void
print_line(const char *buf, size_t max, size_t line_number, size_t line_offset) {
    size_t i;
    size_t line_count = 0;
    const char *line = "";
    size_t line_length = 0;
    
    for (i=0; i<max; i++) {
        if (line_count == line_number)
            break;
        if (buf[i] == '\n')
            line_count++;
    }
    line = &buf[i];
    
    for (i=0; line[i] != '\n' && line[i] != '\r'; i++)
        line_length++;
    
    //fprintf(stderr, "[%.*s]\n", (unsigned)line_length, line);
    fprintf(stderr, "[");
    for (i=0; i<line_length; i++) {
        if (!isprint(line[i]))
            fprintf(stderr, ".");
        else if (isspace(line[i]))
            fprintf(stderr, " ");
        else
            fprintf(stderr, "%c", line[i]);
    }
    fprintf(stderr, "]\n");
    fprintf(stderr, " ");
    for (i=0; i<line_offset; i++) {
        fprintf(stderr, " ");
    }
    fprintf(stderr, "^\n");
    
}
struct block_data {
    size_t bytes_consumed;
    size_t record_count;
    size_t error_line_number;
    size_t error_line_offset;
    size_t parens_line_number;
    size_t parens_line_offset;
    int error_code;
};


static int
test_buffer(const char *in_buf, size_t max, struct block_data *x, size_t pos, char replace) {
    char *buf = malloc(max);
    memcpy(buf, in_buf, max);
    
    /* Replace one character in order to produce an error */
    if (pos)
        buf[pos] = replace;
    
    /* Create a block to parse into */
    zone_block_t *block;
    block = zone_block_create("<buffer>", 0, 0, 0);

    size_t offset = 0;
    
    while (offset < max) {
        offset = zone_block_fill(block, buf, offset, max);
        
        int result;
        
        result = zone_block_scan(block);
        
        /* Produce the results for testing */
        x->error_line_number = block->error_line_number;
        x->error_line_offset = block->error_line_offset;
        x->parens_line_number = block->parens_line_number;
        x->parens_line_offset = block->parens_line_offset;
        x->error_code = block->error_code;
        x->bytes_consumed = block->buf_consumed;
        x->record_count = block->record_count;
        
        if (result == BLOCK_ERROR)
            goto fail;

        
        if (result == BLOCK_INCLUDE) {
            /* Ignore $INCLUDE directive */
            if (block->is_include_filename_seen) {
                free(block->include.filename);
                block->is_include_filename_seen = 0;
            }
            if (block->is_include_origin_seen) {
                free(block->include.origin);
                block->is_include_origin_seen = 0;
            }
            goto fail;
        }
     
        zone_block_t *next = zone_block_next(block);
        zone_block_free(block);
        block = next;
        assert(result == BLOCK_OK);
    }

    free(buf);
    zone_block_free(block);
    return 0;
fail:
    free(buf);
    zone_block_free(block);
    return 1;
}

static void
print_error_message(const char *buf, size_t max, struct block_data x) {
    fprintf(stderr, "%s:%u:%u: parse error #%d: %s\n",
            "test",
            (unsigned)x.error_line_number,
            (unsigned)x.error_line_offset,
            x.error_code,
            zone_error_msg(x.error_code));
    print_line(zonefile, max, x.error_line_number, x.error_line_offset);
    if (x.error_code == ZONE_ERROR_NESTED_PARENS) {
        fprintf(stderr, "%s:%u:%u: previous parentheses located here\n",
                "test",
                (unsigned)x.parens_line_number,
                (unsigned)x.parens_line_offset);
        print_line(zonefile, max, x.parens_line_number, x.parens_line_offset);
    }

}

int zone_scan_tests(void) {
    struct block_data x = {0};
    int err = 0;
    /* Now test the combined/integrated scan */
  
    /*
     * Do a test of the benchmark data to make sure it works
     */
    err = test_buffer(bench_data, strlen(bench_data), &x, 0, 0);
    if (err) {
        print_error_message(zonefile, strlen(bench_data), x);
        return 1;
    }
    
    size_t max = strlen(zonefile);
    int expected_error_code = ZONE_ERROR_NESTED_PARENS;
    err = test_buffer(zonefile, max, &x, 1860+58, '(');
    
    if (err && x.error_code == expected_error_code)
        err = 0;
    
    if (err) {
        print_error_message(zonefile, max, x);
        fprintf(stderr, "[-] scan.scan(): test %d failed\n", 1);
    }
    
    return err;
}

int zone_scan_quicktest(void) {
    int err = 0;
    
    /* First, test the individual scanners */
    err += zone_scan_eol_quicktest();
    err += zone_scan_escape_quicktest();
    err += zone_scan_fast_quicktest();
    err += zone_scan_fast2_quicktest();
    err += zone_scan_name_quicktest();
    err += zone_scan_quote_quicktest();
    err += zone_scan_space_quicktest();
    err += zone_scan_nospace_quicktest();
    err += zone_scan_tests();
    
    if (err) {
        fprintf(stderr, "[-] scan: quicktest failed\n");
        return err;
    }
    return err;
}
