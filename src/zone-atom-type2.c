
#include "zone-parse.h"
#include "zone-parse-types.h"
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>


static const uint8_t zmasks[48] = {
    0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,
    0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,
    0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,
    0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,
    0,   0,   0,   0,   0,   0,   0,   0,
    0,   0,   0,   0,   0,   0,   0,   0
};

/**
 * This is the hash "seed" that will lead to a "perfect-hash" in our
 * hash function, so that there are no collisions.
 */
uint64_t seed = 1771950258;

/**
 * This is the fastest hash-function that I can come up with. My old hash
 * function using FNV1a hash was taking up 20% of the CPU. By using
 * branchless SWAR techniques, we dramatically reduce the the CPU
 * being used here.
 */
static inline unsigned myhash(const char *data, size_t length) {

    /*
     * Clamp length to the first 16 bytes of the string. In
     * practice, all the strings are 10 characters or less anyway.
     */
    length &= 0x1F;

    /*
     * We are guaranteed to have 16 bytes of the TYPE name,
     * either when parsing zonefiles or hashing internal
     * strings. Copy these into two 64-bit nubmers for
     * SWAR-style processing
     */
    uint64_t inputs[2];
    memcpy(&inputs, data, 16);

    /*
     * Use SWAR techniques to make sure the inpu is ALL CAPS.
     */
    static const uint64_t letter_mask = 0x4040404040404040llu;
    inputs[0] = inputs[0] & ~((inputs[0] & letter_mask) >> 1);
    inputs[1] = inputs[1] & ~((inputs[1] & letter_mask) >> 1);
   
    /*
     * Mask off any trailing bytes of input, forcing them
     * to the value of zero.
     */
    uint64_t mask_off[2];
    memcpy(&mask_off, &zmasks[32 - length], 16);
    inputs[0] &= mask_off[0];
    inputs[1] &= mask_off[1];

    /*
     * Do a simplistic "hash" algorithm. We don't need anything
     * complex, because we are going to search for seeds until
     * we find one that evenly distributes the hash-table with
     * no collisions, a "perfect-hash". The key thing is that
     * changing the "seed" will change which strings collide.
     */
    uint64_t output = inputs[0] ^ inputs[1];
    output = ((output >> 32) ^ output);
    output = ((output * seed) >> 32);
    
    return (unsigned)output;
}


static const struct zone_atom_type zone_atom_type_table[] = {
    /* 0: not found / error */
    { 0, "", 0, 0 },
    
    /* 1..3: CLASS */
    { 1, "IN", 0, 0 },
    { 2, "",   0, 0 }, /* placeholder for unknown class */
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

#define TABLESIZE 512
struct zone_atom_hashent {
  uint64_t hash;   /* 0 means empty */
  uint16_t index;  /* 0 means empty (also reserved "not found") */
};

/* Translate from NAME (A, NS. SOA, MX, etc.) to an index in our main table */
static struct zone_atom_hashent name_table[TABLESIZE];

/* Translate from a VALUE (like 1=A, 2=NS, etc.) to an entry
 * in our table. Not really a hash table, by an almost indexed
 * linke back. */
static struct zone_atom_hashent value_table[TABLESIZE];

static int
name_table_insert(const char *name, unsigned length, unsigned index) {
    unsigned hash = myhash(name, length);
    unsigned idx = hash & (TABLESIZE-1);
    struct zone_atom_hashent *e = &name_table[idx];
    
    if (e->index == 0) {
        e->hash  = hash;
        e->index = index;
        return 0; /* success */
    } else
        return 1; /* failure, collision */
}

/**
 * Attempt to insert all the TYPE names that we know about into a hash-table.
 * If there is a collision, then return immediately. The caller will change the
 * the hash-function seed and call us again, until they succeed.
 */
static int name_table_insert_all(void) {
    /*
     * Go through all our TYPEs table and insert a pointer to them
     * from the hash-table.
     */
    for (unsigned i = 1; i < ZONE_ARRLEN(zone_atom_type_table); i++) {
        if (i == 4)
            continue; /* TYPEddd handler has no mnemonic */
        
        if (zone_atom_type_table[i].name[0] == 0)
            continue; /* shouldn't happen */
        
        const char *name = zone_atom_type_table[i].name;
        int collision = name_table_insert(name, (unsigned)strlen(name), i);
        if (collision > 0)
            return collision; /* duplicate hash, re-seed and try again */
    }
    return 0;
}

const struct zone_atom_type *zone_type2_by_index(unsigned idx) {
    return &zone_atom_type_table[idx];
}

void
zone_types2_init(void)
{
    /*
     * Our first attempt should be a large 32-bit number.
     * One possible first attempt is the hard-code seed above.
     * Otherwise, `time(0)` is a good random large number to
     * start from.
     */
    //seed = time(0);
    
    /*
     * Brute force seeds until we find one that delivers a
     * "perfect-hash".
     */
    for (;;) {
        
        /*
         * Clear the hash-table, resetting after our previous
         * attempt in a previous iteration of this loop.
         */
        memset(name_table, 0, sizeof(name_table));
        
        /*
         * Insert all the TYPE names.
         */
        int count = name_table_insert_all();
        
        /*
         * If they are all unique, then we are done.
         */
        if (count == 0)
            break;
        
        /*
         * Otherwise, increate the SEED and try again
         */
        seed++;
    }
    
    /*
     * Do some quick tests
     */
    {
        unsigned value = 0;
        unsigned idx = zone_type2_lookup("A                ", 1, &value);
        assert(value == 1);
        assert(idx == 6);
    }
    
    /*
     * Now build the VALUE table, reverse mapping from the number
     * back to the master table enry that will have the string NAME
     * and callbacks.
     */
    for (unsigned i=1; i<=264; i++) {
        unsigned idx = i + 5; /*first 5 entries are special) */
        while (idx < ZONE_ARRLEN(zone_atom_type_table)) {
            if (zone_atom_type_table[idx].value == i)
                break;
            idx++;
        }
        if (idx >= TABLESIZE)
            break;
        value_table[i].index = idx;
    }
    
    {
        unsigned idx = zone_type2_lookup_val(1);
        assert(idx == 6);
    }
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

unsigned zone_type2_lookup_val(unsigned value) {
    unsigned val2;
    if (value < TABLESIZE)
        return value_table[value].index;
    else if (value == 32768)
        return zone_type2_lookup("TA                ", 2, &val2);
    else if (value == 32769)
        return zone_type2_lookup("DLV               ",  3, &val2);
    else
        return 0;
}


#if BYTE_ORDER == LITTLE_ENDIAN
static const uint64_t TYPE_NAME  = 0x0000000045505954llu;
static const uint64_t TYPE_MASK  = 0x00000000ffffffffllu;
static const uint64_t CLASS_NAME = 0x0000005353414c43llu;
static const uint64_t CLASS_MASK = 0x000000ffffffffffllu;
#else
static const uint64_t TYPE_NAME  = 0x5459504500000000llu;
static const uint64_t TYPE_MASK  = 0xffffffff00000000llu;
static const uint64_t CLASS_NAME = 0x434c415353000000llu;
static const uint64_t CLASS_MASK = 0xffffffffff000000llu;
#endif

unsigned
zone_type2_lookup( const char * restrict name, size_t length, unsigned * restrict type_value) {
    
    /*
     * Lookup the name
     */
    uint64_t hash = myhash(name, length);
    unsigned idx = (unsigned)(hash & (TABLESIZE-1));
    idx = name_table[idx].index;
    if (idx) {
        *type_value = zone_atom_type_table[idx].value;
        return idx;
    }
    
    /*
     * Not found, maybe we have a TYPEddd instead.
     */
    uint64_t input;
    memcpy(&input, name, 8);
    if ((input & TYPE_MASK) == TYPE_NAME) {
        uint16_t value = 0;
        if (parse_u16(name + 4, length - 4, &value)) {
            *type_value = value;
            unsigned idx = zone_type2_lookup_val(value);
            if (idx)
                return idx;
            else
                return 4; /* unknown/not-found */
        }
    }

    return 0;
}

