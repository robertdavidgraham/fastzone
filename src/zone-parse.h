#ifndef ZONE_PARSE_H
#define ZONE_PARSE_H
#include "zone-parse-mask.h"
#include "zone-error.h"
#include "zone-atom-name.h"
#include <stddef.h>
#include <stdint.h>


void zone_parse_init(int backend);
int zone_parse_quicktest(void);

/* Optional: pick scalar backend for determinism */
extern void zone_parse_header2_init(int simd);
extern int zone_parse_header_quicktest(void);

/* ------------------------------ expected project API ---------------------- */
/* Provide these in your project headers; declared here as externs. */

typedef struct wire_record_t {
    unsigned line_count;
    size_t name_length;
    unsigned is_fqdn:1;
    
    struct {
        unsigned char *buf;
        size_t len;
        size_t max;
    } wire;
    
    struct {
        int code;
        size_t cursor;
    } err;
    
    struct {
        const unsigned char *origin;
        size_t origin_length;
        unsigned default_ttl;
    } state;
    
    struct {
        unsigned idx;
        unsigned value;
    } rrtype;
    
} wire_record_t;


#ifndef ZONE_HDR_F_TTL
#define ZONE_HDR_F_TTL   0x00000001u
#define ZONE_HDR_F_CLASS 0x00000002u
#define ZONE_HDR_F_TYPE  0x00000004u
//#define ZONE_NAM_F_FQDN  0x00000008u
#endif

/* Keyword lookup:
 *   0      => unknown
 *   1..4   => CLASS id (1==IN)
 *   >=5    => TYPE table index = v-5
 */
extern uint16_t zone_kw_lookup(const char *s, size_t n);

typedef struct zone_rrtype_desc {
    uint16_t type_code;
    const char *name;
    void *parser;
    void *formatter;
} zone_rrtype_desc;


struct wire_record_t;

size_t
zone_parse_header(const char *data, size_t i, size_t max, struct wire_record_t *out, unsigned *depth);
size_t
zone_parse_header2(const char *data, size_t i, size_t max, struct wire_record_t *out, unsigned *depth);

int zone_parse_header2_quicktest(void);



size_t
parse_ttl_seconds(const char *data, size_t cursor, size_t length,
                  unsigned *ttl_out, int *err);
size_t
parse_ttl_fast(const char *data, size_t cursor, size_t length,
                  unsigned *ttl_out, int *err);

extern unsigned zone_type1_lookup( const char * restrict data, size_t length,  unsigned * restrict type_value);
extern unsigned zone_type2_lookup( const char * restrict name, size_t length, unsigned * restrict type_value);
extern unsigned zone_type2_lookup_val(unsigned value);

struct wire_record_t;
typedef size_t (*zone_rdata_parser_fn)(const char *data, size_t cursor, size_t max,
                                       struct wire_record_t *out,
                                       unsigned *depth);
typedef int (*zone_rdata_format_fn)(void *ctx, char *dst, size_t dstcap);

struct zone_atom_type {
  uint16_t value;
  const char name[16]; /* ALL CAPS mnemonic, or NULL */
  zone_rdata_parser_fn parse;
  zone_rdata_format_fn format;
};

static inline size_t PARSE_ERR(int err, size_t cursor, size_t max, struct wire_record_t *out) {
    if (out->err.code == 0) {
        out->err.code = err;
        out->err.cursor = cursor;
    }
    return max + 1;
}


size_t
zone_atom_ttl(const char *data, size_t cursor, size_t max,
               struct wire_record_t *out);

extern const struct zone_atom_type *zone_type1_by_index(unsigned idx);
extern const struct zone_atom_type *zone_type2_by_index(unsigned idx);


void wire_append_uint32(struct wire_record_t *out, unsigned value);
void wire_append_uint16(struct wire_record_t *out, unsigned value);
void wire_append_uint8(struct wire_record_t *out, unsigned value);
void wire_append_bytes(struct wire_record_t *out, const unsigned char *value, size_t length);

/**
 * Given a TYPE by it's number, find it's string name
 */
const char *zone_name_from_type(unsigned value);

#endif

