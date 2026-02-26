/* zone-atom-type.c
 *
 * DNS zonefile TYPE / CLASS atom table and lookup
 * ==============================================
 *
 * REGENERATION SPECIFICATION (AUTHORITATIVE)
 * ------------------------------------------
 * This file MUST be regenerated (not edited by hand) if any of these rules change.
 *
 * 1) Atom table
 * -------------
 * The master atom table is a flat array:
 *
 *   struct zone_atom_type {
 *     uint16_t value;          // numeric TYPE or CLASS value
 *     const char *name;        // uppercase mnemonic, or NULL
 *     zone_rdata_parser_fn  parse;   // rdata parser (0 if not implemented)
 *     zone_rdata_format_fn  format;  // rdata formatter (0 if not implemented)
 *   };
 *
 * Index semantics:
 *   - index 0: reserved "not found / error"
 *       { value=0, name=NULL, parse=0, format=0 }
 *
 *   - index 1..3: reserved CLASS atoms (their numeric values are CLASS values):
 *       index 1: IN (value=1)
 *       index 2: CH (value=3)
 *       index 3: HS (value=4)
 *
 *   - index 4: reserved generic TYPEddd handler
 *       Represents tokens of the form "TYPE" <decimal u16>.
 *       This entry provides the parse/format function pointers for RFC3597-style
 *       generic handling. (You may leave parse/format as 0 for now.)
 *
 *   - index >= 5: RR TYPE atoms (IANA registry)
 *       value = RR TYPE numeric value
 *       name  = mnemonic (ALL CAPS), including "*" for QTYPE ANY (255)
 *       parse/format = 0 initially; user fills in when implemented.
 *
 * 2) Hash table
 * -------------
 * A fixed-size open-addressed hash table of 1024 entries:
 *
 *   struct zone_atom_hashent {
 *     uint64_t hash;    // 0 means empty
 *     uint16_t index;   // index into zone_atom_type_table[]
 *   };
 *
 * Hashing:
 *   - 64-bit FNV-1a over ASCII-uppercase bytes of the mnemonic.
 *   - base index = low 9 bits (hash & 511).
 *   - linear probe forward on collision.
 *   - insertion at first empty slot.
 *
 * 3) Lookup API
 * -------------
 *   uint16_t zone_atom_type_lookup(const char *s, size_t n);
 *
 *   - Returns the INDEX into zone_atom_type_table[].
 *   - Returns 0 on error / not found.
 *   - Case-insensitive (ASCII only, no locale).
 *
 * TYPEddd special-case:
 *   - If token matches /^TYPE[0-9]+$/i and value parses as uint16_t:
 *       returns 4
 *       the numeric TYPE value is stored in a static scratch atom
 *       accessible via zone_atom_type_at(4)->value.
 *
 * 4) Data source for RR TYPE list
 * -------------------------------
 * RR TYPE mnemonics and numeric values correspond to the IANA "Resource Record (RR) TYPEs"
 * registry (DNS Parameters), Last Updated 2025-12-29.
 *
 * 5) No SIMD, no locale, ASCII only.
 */
#include "zone-parse.h"
#include "zone-parse-types.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <assert.h>


struct zone_atom_hashent {
  uint64_t hash;   /* 0 means empty */
  uint16_t index;  /* 0 means empty (also reserved "not found") */
};

#define TABLESIZE 512

//#define ZONE_ARRLEN(x) (sizeof(x) / sizeof((x)[0]))

/* ---- ASCII helpers ---- */

static inline unsigned char
zone_upper(unsigned char c)
{
    return c & ~0x20;
}

#define HASH fnv1a64_seeded
static unsigned seed = 50272;
static uint64_t
zone_hash64_upper_fnv1a(const char *s, size_t n)
{
  uint64_t h = 1469598103934665603ULL; /* FNV offset basis (64-bit) */
    h *= seed;
  for (size_t i = 0; i < n; i++) {
    h ^= (uint64_t)(s[i] | 0x20);
    h *= 1099511628211ULL; /* FNV prime (64-bit) */
  }
  /* reserve 0 as empty marker */
  if (h == 0) h = 1;
  return h>>32ull;
}
static inline uint64_t fmix64(uint64_t x) {
    // MurmurHash3 finalizer (good avalanche)
    x ^= x >> 33;
    x *= 0xff51afd7ed558ccdULL;
    x ^= x >> 33;
    x *= 0xc4ceb9fe1a85ec53ULL;
    x ^= x >> 33;
    return x;
}

static uint64_t hh = 1469598103934665603ULL;
static void set_seed(unsigned in_seed) {
    seed = in_seed;
    hh = 1469598103934665603ULL;

    // Mix seed into the stream (8 bytes)
    uint64_t s = seed;
    for (int i = 0; i < 8; i++) {
        hh ^= (uint8_t)(s & 0xFF);
        hh *= 1099511628211ULL;
        s >>= 8;
    }
}

static inline uint64_t fnv1a64_seeded(const void *data, size_t len)  {
    const uint8_t *p = (const uint8_t*)data;

    // FNV offset basis (64-bit)
    uint64_t h = hh;
    
    // Hash key bytes
    for (size_t i = 0; i < len; i++) {
        h ^= p[i];
        h *= 1099511628211ULL;
    }

    // Final avalanche to fix low-bit weakness
    return fmix64(h);
}

static int
zone_caseeq_token(const char *tok, size_t toklen, const char *name_z)
{
  /* name_z is NUL-terminated uppercase mnemonic */
  for (size_t i = 0; i < toklen; i++) {
    unsigned char a = zone_upper(tok[i]);
    unsigned char b = zone_upper(name_z[i]);
    //if (b == 0) return 0;     /* name shorter than token */
    if (a != b) return 0;
  }
  return name_z[toklen] == 0; /* ensure same length */
}

static int
parse_u16(const char *s, size_t length, uint16_t *out)
{
    if (length == 0)
        return 0;
    unsigned value = 0;
    
    for (size_t i = 0; i < length; i++) {
        unsigned char c = s[i];
        if (c < '0' || c > '9')
            return 0;
        value = value * 10 + (c - '0');
        if (value > 65535u)
            return 0;
    }
    *out = (uint16_t)value;
    return 1;
}

/* ---- master atom table ---- */

static const struct zone_atom_type zone_atom_type_table[] = {
  /* 0: not found / error */
  { 0, "", 0, 0 },

  /* 1..3: CLASS */
  { 1, "IN", 0, 0 },
  { 3, "CH", 0, 0 },
  { 4, "HS", 0, 0 },

  /* 4: generic TYPEddd handler (template: parse/format may be set later) */
  { 0, "", 0, 0 },

  /* >=5: RR TYPE atoms (IANA registry assignments) */

  { 1,   "A",        zone_parse_A, 0 },
  { 2,   "NS",       zone_parse_NS, 0 },
  { 3,   "MD",       0, 0 },
  { 4,   "MF",       0, 0 },
  { 5,   "CNAME",    zone_parse_CNAME, 0 },
  { 6,   "SOA",      zone_parse_SOA, 0 },
  { 7,   "MB",       0, 0 },
  { 8,   "MG",       0, 0 },
  { 9,   "MR",       0, 0 },
  { 10,  "NULL",     0, 0 },
  { 11,  "WKS",      0, 0 },
  { 12,  "PTR",      zone_parse_PTR, 0 },
  { 13,  "HINFO",    0, 0 },
  { 14,  "MINFO",    0, 0 },
  { 15,  "MX",       zone_parse_MX, 0 },
  { 16,  "TXT",      zone_parse_TXT, 0 },
  { 17,  "RP",       0, 0 },
  { 18,  "AFSDB",    0, 0 },
  { 19,  "X25",      0, 0 },
  { 20,  "ISDN",     0, 0 },
  { 21,  "RT",       0, 0 },
  { 22,  "NSAP",     0, 0 },
  { 23,  "NSAP-PTR", 0, 0 },
  { 24,  "SIG",      0, 0 },
  { 25,  "KEY",      0, 0 },
  { 26,  "PX",       0, 0 },
  { 27,  "GPOS",     0, 0 },
  { 28,  "AAAA",     zone_parse_AAAA, 0 },
  { 29,  "LOC",      0, 0 },
  { 30,  "NXT",      0, 0 },
  { 31,  "EID",      0, 0 },
  { 32,  "NIMLOC",   0, 0 },
  { 33,  "SRV",      zone_parse_SRV, 0 },
  { 34,  "ATMA",     0, 0 },
  { 35,  "NAPTR",    zone_parse_NAPTR, 0 },
  { 36,  "KX",       0, 0 },
  { 37,  "CERT",     0, 0 },
  { 38,  "A6",       0, 0 },
  { 39,  "DNAME",    zone_parse_DNAME, 0 },
  { 40,  "SINK",     0, 0 },
  { 41,  "OPT",      0, 0 },
  { 42,  "APL",      0, 0 },
  { 43,  "DS",       zone_parse_DS, 0 },
  { 44,  "SSHFP",    zone_parse_SSHFP, 0 },
  { 45,  "IPSECKEY", zone_parse_IPSECKEY, 0 },
  { 46,  "RRSIG",    zone_parse_RRSIG, 0 },
  { 47,  "NSEC",     zone_parse_NSEC, 0 },
  { 48,  "DNSKEY",   zone_parse_DNSKEY, 0 },
  { 49,  "DHCID",    0, 0 },
  { 50,  "NSEC3",    zone_parse_NSEC3, 0 },
  { 51,  "NSEC3PARAM",0, 0 },
  { 52,  "TLSA",     zone_parse_TLSA, 0 },
  { 53,  "SMIMEA",   zone_parse_SMIMEA, 0 },
  { 55,  "HIP",      0, 0 },
  { 56,  "NINFO",    0, 0 },
  { 57,  "RKEY",     0, 0 },
  { 58,  "TALINK",   0, 0 },
  { 59,  "CDS",      0, 0 },
  { 60,  "CDNSKEY",  0, 0 },
  { 61,  "OPENPGPKEY",0, 0 },
  { 62,  "CSYNC",    0, 0 },
  { 63,  "ZONEMD",   zone_parse_ZONEMD, 0 },
  { 64,  "SVCB",     zone_parse_SVCB, 0 },
  { 65,  "HTTPS",    zone_parse_HTTPS, 0 },
  { 66,  "DSYNC",    0, 0 },
  { 67,  "HHIT",     0, 0 },
  { 68,  "BRID",     0, 0 },

  { 99,  "SPF",      zone_parse_SPF, 0 },
  { 100, "UINFO",    0, 0 },
  { 101, "UID",      0, 0 },
  { 102, "GID",      0, 0 },
  { 103, "UNSPEC",   0, 0 },
  { 104, "NID",      0, 0 },
  { 105, "L32",      0, 0 },
  { 106, "L64",      0, 0 },
  { 107, "LP",       0, 0 },
  { 108, "EUI48",    0, 0 },
  { 109, "EUI64",    0, 0 },

  { 128, "NXNAME",   0, 0 },

  { 249, "TKEY",     0, 0 },
  { 250, "TSIG",     0, 0 },
  { 251, "IXFR",     0, 0 },
  { 252, "AXFR",     0, 0 },
  { 253, "MAILB",    0, 0 },
  { 254, "MAILA",    0, 0 },
  { 255, "*",        0, 0 },

  { 256, "URI",      zone_parse_URI, 0 },
  { 257, "CAA",      zone_parse_CAA, 0 },
  { 258, "AVC",      0, 0 },
  { 259, "DOA",      0, 0 },
  { 260, "AMTRELAY", 0, 0 },
  { 261, "RESINFO",  0, 0 },
  { 262, "WALLET",   0, 0 },
  { 263, "CLA",      0, 0 },
  { 264, "IPN",      0, 0 },

  { 32768, "TA",     0, 0 },
  { 32769, "DLV",    0, 0 },
};
#define ZONE_ARRLEN(x) (sizeof(x)/sizeof(x[0]))

const struct zone_atom_type *zone_type_by_index(unsigned idx) {
    return &zone_atom_type_table[idx];
}

/* ---- TYPEddd scratch atom (index 4 uses this for the value) ---- */

static struct zone_atom_type zone_atom_type_scratch_type = {
  0, "", 0, 0
};

/* Return pointer to atom by index, including TYPEddd scratch. */
const struct zone_atom_type *
zone_atom_type_at(uint16_t idx)
{
  if (idx == 4) return &zone_atom_type_scratch_type;
  if (idx < (uint16_t)ZONE_ARRLEN(zone_atom_type_table)) return &zone_atom_type_table[idx];
  return &zone_atom_type_table[0];
}



/* ---- 512-entry hash table ---- */

static struct zone_atom_hashent name_table[TABLESIZE];
static struct zone_atom_hashent value_table[TABLESIZE];
#include <stdio.h>

static int
name_table_insert(uint16_t idx) {
    const char *name = zone_atom_type_table[idx].name;

    if (!name) return 1;
    
    const size_t length = strlen(name);
    const uint64_t h = HASH(name, length);
    const uint32_t base = (uint32_t)(h & (TABLESIZE-1));
    
    uint32_t step;
    /*if (name[0] == 'S' && name[1] == 'R' && name[2] == 'V')
        printf(".");*/
    for (step = 0; step < TABLESIZE; step++) {
        struct zone_atom_hashent *e = &name_table[(base + step) & (TABLESIZE-1)];
        
        if (e->index == 0) {
            e->hash  = h;
            e->index = idx;
            return step;
        }
        
        /* If same hash and same name, treat as duplicate and ignore. */
        if (e->hash == h) {
            const uint16_t prev = e->index;
            const char *pname = zone_atom_type_table[prev].name;
            if (pname && zone_caseeq_token(name, length, pname)) {
                return step;
            }
        }
        
        step += 0;
    }
    
    /* Table full: by spec we do not rehash; caller gets lookup misses. */
    return step;
}

static void
value_table_insert(uint16_t idx)
{
  unsigned value = zone_atom_type_table[idx].value;
  if (!value) return;

  const uint64_t h = HASH((void*)&value, 4);
  const uint32_t base = (uint32_t)(h & (TABLESIZE-1));

  for (uint32_t step = 0; step < TABLESIZE; step++) {
    struct zone_atom_hashent *e = &value_table[(base + step) & (TABLESIZE-1)];

    if (e->index == 0) {
      e->hash  = h;
      e->index = idx;
      return;
    }

    /* If same hash and same name, treat as duplicate and ignore. */
    if (e->hash == h) {
      const uint16_t prev = e->index;
      if (value == zone_atom_type_table[prev].value)
          return;
    }
  }

  /* Table full: by spec we do not rehash; caller gets lookup misses. */
}

static int name_table_insert_all(void) {
    int count = 0;
    
    /* Insert CLASS atoms too (indices 1..3), plus all RR TYPE atoms (>=5). */
    for (uint16_t i = 1; i < (uint16_t)ZONE_ARRLEN(zone_atom_type_table); i++) {
        if (i == 4) continue; /* TYPEddd handler has no mnemonic */
        
        if (zone_atom_type_table[i].name[0] != 0) {
            
            /* look up by name */
            int c = name_table_insert(i);
            if (count < c)
                count = c;
        }
    }
    return count;
}

static int value_table_insert_all(void) {
    /* Insert CLASS atoms too (indices 1..3), plus all RR TYPE atoms (>=5). */
    for (uint16_t i = 1; i < (uint16_t)ZONE_ARRLEN(zone_atom_type_table); i++) {
        if (i == 4) continue; /* TYPEddd handler has no mnemonic */
        
        if (zone_atom_type_table[i].name[0] != 0) {
            /* lookup by value (ignore CLASS, only TYPE) */
            if (i > 4)
                value_table_insert(i);
        }
    }
    return 1;
}

#include <stdio.h>

void
zone_atom_ht_init(void)
{
    set_seed(50272);
    static int zone_atom_ht_ready = 0;
    unsigned i;
    if (zone_atom_ht_ready)
        return;
    
    memset(name_table, 0, sizeof(name_table));
    memset(value_table, 0, sizeof(value_table));
    
    for (i=0; ; i++) {
        int count = name_table_insert_all();
        if (count > 0) {
            memset(name_table, 0, sizeof(name_table));
            set_seed(seed++);
        } else
            break;
    }
    printf("tries = %u\n", i);
    zone_atom_ht_ready = 1;

    unsigned value = 0;
    unsigned idx = zone_type1_lookup("SRV", 3, &value);
    assert(value == 33);
    assert(idx == 37);
    value_table_insert_all();
    
}



/* ---- lookup ---- */

unsigned
zone_atom_type_lookup_val(unsigned value) {
    zone_atom_ht_init();
    
    const uint64_t h = HASH((char*)&value, sizeof(value));
    const uint32_t base = (uint32_t)(h & (TABLESIZE-1));
    
    for (uint32_t step = 0; step < TABLESIZE; step++) {
        const struct zone_atom_hashent *e = &value_table[(base + step) & (TABLESIZE-1)];
        
        if (e->index == 0) {
            /* first empty slot => not present (because inserts stop at first empty) */
            return 0;
        }
        
        if (e->hash == h) {
            const uint16_t idx = e->index;
            if (value == zone_atom_type_table[idx].value)
                return idx;
        }
    }
    
    return 0;
}

const char *
zone_name_from_type(unsigned value) {
    unsigned idx = zone_atom_type_lookup_val(value);
    if (idx > 4)
        return zone_atom_type_table[idx].name;
    else
        return "UNKNOWN";
}

unsigned
zone_type1_lookup( const char * restrict data, size_t length, unsigned * restrict type_value) {

    /* TYPEddd handling */
    if (length >= 5 && 
        zone_upper((unsigned char)data[0]) == 'T' &&
        zone_upper((unsigned char)data[1]) == 'Y' &&
        zone_upper((unsigned char)data[2]) == 'P' &&
        zone_upper((unsigned char)data[3]) == 'E') {
        
        uint16_t value = 0;
        if (parse_u16(data + 4, length - 4, &value)) {
            *type_value = value;
            unsigned idx = zone_atom_type_lookup_val(value);
            if (idx)
                return idx;
            else
                return 4; /* unknown/not-found */
        }
    }
    
    const uint64_t hash = HASH(data, length);
    const uint32_t idx = (uint32_t)(hash & (TABLESIZE-1));
    
    //printf("%u\n", name_table[idx].index);
    *type_value = zone_atom_type_table[name_table[idx].index].value;
    return name_table[idx].index;
#if 0
    for (uint32_t step = 0; step < TABLESIZE; step++) {
        const struct zone_atom_hashent *e = &name_table[(idx + step) & (TABLESIZE-1)];
        
        if (e->index == 0) {
            /* first empty slot => not present (because inserts stop at first empty) */
            return 0;
        }
        
        if (e->hash == hash) {
            const uint16_t idx = e->index;
            const char *name = zone_atom_type_table[idx].name;
            *type_value = zone_atom_type_table[idx].value;
            if (name && zone_caseeq_token(data, length, name)) {
                return idx;
            }
        }
    }
    
    return 0;
#endif
}
