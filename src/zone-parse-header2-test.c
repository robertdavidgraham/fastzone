#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "zone-parse.h"
#include "util-simd.h"

/* Under test */
extern size_t
zone_parse_header2(const char *data, size_t cursor, size_t max,
                   struct wire_record_t *out,
                   unsigned *depth);






static int
run_one_case(const char *label,
             const char *data,
             size_t cursor,
             size_t max,
             size_t expect_cursor,
             unsigned index)
{
    static const uint8_t expect8[8] = {
        0x00,0x02, /* NS */
        0x00,0x01, /* IN */
        0x00,0x00,0x0E,0x10 /* 3600 */
    };

    uint8_t wirebuf[64];
    memset(wirebuf, 0, sizeof(wirebuf));

    struct wire_record_t out;
    memset(&out, 0, sizeof(out));
    out.wire.buf = wirebuf;
    out.wire.len = 0;
    out.wire.max = 1024;
    out.state.default_ttl = 3600;

    unsigned depth = 0;
    if (index == 37)
        printf("%s\n", data + cursor);
    size_t newc = zone_parse_header2(data, cursor, max, &out, &depth);

    int is_bad = 0;

    if (newc != expect_cursor) {
        printf("FAIL %-24s cursor=%zu expect=%zu\n", label, newc, expect_cursor);
        is_bad = 1;
    }
    if (out.wire.len != 8) {
        printf("FAIL %-24s wire.len=%zu expect=8\n", label, (size_t)out.wire.len);
        is_bad = 1;
    }
    if (memcmp(wirebuf, expect8, 8) != 0) {
        printf("FAIL = [%u %u %u]\n",
               wirebuf[0]<<8 | wirebuf[1],
               wirebuf[2]<<8 | wirebuf[3],
               wirebuf[4]<<24 | wirebuf[5]<<16 | wirebuf[6]<<8 | wirebuf[7]
        );
        printf("EXPECT = [%u %u %u]\n",
               expect8[0]<<8 | expect8[1],
               expect8[2]<<8 | expect8[3],
               expect8[4]<<24 | expect8[5]<<16 | expect8[6]<<8 | expect8[7]
        );
        
        is_bad = 1;
    }

    return is_bad;
}
#include <stdlib.h>
#include <assert.h>

static size_t fill(char *line, size_t offset, size_t count) {
    memset(line + offset, ' ', count);
    return offset + count;
}
static size_t append(char *line, size_t offset, const char *src, size_t src_length) {
    memcpy(line+offset, src, src_length);
    return offset + src_length;
}

char *build_line(unsigned sp1, unsigned sp2, unsigned sp3, unsigned sp4,
                        const char *rrttl,
                        const char *rrclass,
                        const char *rrtype,
                        const char *rrdata,
                 size_t *expect_cursor) {
    size_t rrttl_length = strlen(rrttl);
    size_t rrclass_length = strlen(rrclass);
    size_t rrtype_length = strlen(rrtype);
    size_t rrdata_length = strlen(rrdata);
    
    size_t total_length = sp1 + sp2 + sp3 + sp4 +
        rrttl_length + rrclass_length + rrtype_length + rrdata_length;
    
    char *line = malloc(total_length + 1024);
    size_t offset = 0;
    
    offset = fill(line, offset, sp1+1);
    offset = append(line, offset, rrttl, rrttl_length);
    offset = fill(line, offset, sp2+1);
    offset = append(line, offset, rrclass, rrclass_length);
    offset = fill(line, offset, sp3+1);
    offset = append(line, offset, rrtype, rrtype_length);
    offset = fill(line, offset, sp4+1);
    *expect_cursor = offset;
    offset = append(line, offset, rrdata, rrdata_length);

    memcpy(line+offset, "\n \n \n \n \n", 10);
    return line;
}

int do_test(unsigned sp1, unsigned sp2, unsigned sp3, unsigned sp4, unsigned inc, unsigned index) {
    size_t expect_cursor;
    char *line = build_line(sp1, sp2, sp3, sp4,
                            (inc&1)?"3600":"",
                            (inc&2)?"IN":"",
                            "NS",
                            "ns.example.com\n",
                            &expect_cursor);
    
    int err = run_one_case("",
                           line,
                           0,
                           1000,
                           expect_cursor,
                           index);
    free(line);
    return err;
}
int
zone_parse_header2_quicktest(void)
{
    int err = 0;

    for (unsigned i=0; i<66*66*66*66*4; i++) {
        unsigned foo = i;
        unsigned sp1 = foo & 66;
        foo /= 66;
        unsigned sp2 = foo & 66;
        foo /= 66;
        unsigned sp3 = foo & 66;
        foo /= 66;
        unsigned sp4 = foo & 66;
        foo /= 66;

        assert(foo < 4);
        err += do_test(sp1, sp2, sp3, sp4, foo, i);

    }

    return err;
}
