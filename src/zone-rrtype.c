// zone_rrtype_lookup.c
#include "zone-rrtype.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>


// -----------------------------------------------------------------------------
// ASCII helpers (DNS mnemonics are ASCII).
// -----------------------------------------------------------------------------

static inline uint8_t ascii_upper(uint8_t c) {
  if (c >= (uint8_t)'a' && c <= (uint8_t)'z') return (uint8_t)(c - 32);
  return c;
}

static int ascii_ieq_n(const char *a, size_t a_len, const char *b_nul) {
  for (size_t i = 0; i < a_len; i++) {
    uint8_t ac = ascii_upper((uint8_t)a[i]);
    uint8_t bc = ascii_upper((uint8_t)b_nul[i]);
    if (bc == 0) return 0;
    if (ac != bc) return 0;
  }
  return b_nul[a_len] == '\0';
}

static uint32_t fnv1a_u32_ascii_upper(const char *s, size_t n) {
  uint32_t h = 2166136261u;
  for (size_t i = 0; i < n; i++) {
    h ^= (uint32_t)ascii_upper((uint8_t)s[i]);
    h *= 16777619u;
  }
  return h;
}

static uint32_t fnv1a_u32_u16(uint16_t v) {
  // FNV-1a over two bytes (little-endian in hash domain; doesn't matter as long
  // as consistent).
  uint32_t h = 2166136261u;
  h ^= (uint8_t)(v & 0xFFu);      h *= 16777619u;
  h ^= (uint8_t)((v >> 8) & 0xFFu); h *= 16777619u;
  return h;
}

// -----------------------------------------------------------------------------
// Generic RFC3597 "\#" formatter/parser for unknown RR types.
// Format: "\# <len> <hexbytes>" where hexbytes is 2*len hex digits.
// -----------------------------------------------------------------------------

static inline int hexval(uint8_t c) {
  if (c >= '0' && c <= '9') return (int)(c - '0');
  c = ascii_upper(c);
  if (c >= 'A' && c <= 'F') return (int)(c - 'A' + 10);
  return -1;
}

static int rrdata_format_generic_hash(char *dst, size_t dst_len,
                                      const uint8_t *rdata, size_t rdata_len) {
  // Writes: "\# " + decimal_len + " " + 2*len hex digits
  // Returns number of bytes written (excluding NUL) or -1 for insufficient space.
  // (You can change this signature later; for now it's useful.)
  if (!dst || dst_len == 0) return -1;

  // Worst-case decimal digits for len (<=65535): 5
  // Fixed overhead: 3 ("\\# ") + 1 space + NUL
  // Hex: 2*len
  // Total worst-case: 3 + 5 + 1 + 2*len + 1
  size_t need_min = 3 + 1 + 1; // "\# " + " " + NUL, plus digits later
  if (dst_len < need_min) return -1;

  size_t pos = 0;
  dst[pos++] = '\\';
  dst[pos++] = '#';
  dst[pos++] = ' ';

  // Write decimal length
  char tmp[6];
  size_t t = 0;
  uint32_t v = (uint32_t)rdata_len;
  if (v == 0) {
    tmp[t++] = '0';
  } else {
    while (v != 0 && t < sizeof(tmp)) {
      tmp[t++] = (char)('0' + (v % 10u));
      v /= 10u;
    }
  }
  if (pos + t + 1 >= dst_len) return -1; // +1 for space or NUL later

  // reverse digits
  for (size_t i = 0; i < t; i++) dst[pos++] = tmp[t - 1 - i];

  dst[pos++] = ' ';
  if (pos >= dst_len) return -1;

  // Hex bytes
  static const char hexd[16] = "0123456789ABCDEF";
  size_t hex_need = 2u * rdata_len;
  if (pos + hex_need + 1 > dst_len) return -1;

  for (size_t i = 0; i < rdata_len; i++) {
    uint8_t b = rdata[i];
    dst[pos++] = hexd[(b >> 4) & 0xFu];
    dst[pos++] = hexd[b & 0xFu];
  }

  dst[pos] = '\0';
  return (int)pos;
}

static int rrdata_parse_generic_hash(const char *s, size_t s_len,
                                     uint8_t *out_rdata, size_t *inout_rdata_len) {
  // Parses: "\# <len> <hexbytes>"
  // Returns 0 on success, negative on failure.
  if (!s || !inout_rdata_len) return -2;
  if (s_len < 2) return -2;

  size_t i = 0;
  if (s[i++] != '\\') return -2;
  if (i >= s_len || s[i++] != '#') return -2;

  // optional whitespace
  while (i < s_len && (s[i] == ' ' || s[i] == '\t')) i++;
  if (i >= s_len) return -2;

  // parse decimal length
  uint32_t len = 0;
  if (s[i] < '0' || s[i] > '9') return -2;
  while (i < s_len && s[i] >= '0' && s[i] <= '9') {
    len = len * 10u + (uint32_t)(s[i] - '0');
    if (len > 65535u) return -2;
    i++;
  }

  // whitespace
  while (i < s_len && (s[i] == ' ' || s[i] == '\t')) i++;
  if (i > s_len) return -2;

  // Now expect exactly 2*len hex digits (allow trailing whitespace after)
  size_t hex_digits = 0;
  size_t hex_start = i;
  while (i < s_len) {
    char c = s[i];
    if (c == ' ' || c == '\t' || c == '\r' || c == '\n') break;
    if (hexval((uint8_t)c) < 0) return -2;
    hex_digits++;
    i++;
  }

  if (hex_digits != (size_t)(2u * len)) return -2;

  // trailing whitespace ok
  while (i < s_len) {
    char c = s[i];
    if (!(c == ' ' || c == '\t' || c == '\r' || c == '\n')) return -2;
    i++;
  }

  if (!out_rdata) {
    // Size query mode: report required length.
    *inout_rdata_len = (size_t)len;
    return 0;
  }

  if (*inout_rdata_len < (size_t)len) return -3;
  *inout_rdata_len = (size_t)len;

  // decode
  for (size_t j = 0; j < (size_t)len; j++) {
    int hi = hexval((uint8_t)s[hex_start + 2*j]);
    int lo = hexval((uint8_t)s[hex_start + 2*j + 1]);
    out_rdata[j] = (uint8_t)((hi << 4) | lo);
  }

  return 0;
}

// -----------------------------------------------------------------------------
// RR TYPE table. (format/parsers are 0, as requested.)
// -----------------------------------------------------------------------------

static const struct rrtype_t g_rrtypes[] = {
  { 0,     "RESERVED", 0, { 0,0,0,0,0,0,0,0,0,0 } },

  { 1,     "A",        0, { 0,0,0,0,0,0,0,0,0,0 } },
  { 2,     "NS",       0, { 0,0,0,0,0,0,0,0,0,0 } },
  { 3,     "MD",       0, { 0,0,0,0,0,0,0,0,0,0 } },
  { 4,     "MF",       0, { 0,0,0,0,0,0,0,0,0,0 } },
  { 5,     "CNAME",    0, { 0,0,0,0,0,0,0,0,0,0 } },
  { 6,     "SOA",      0, { 0,0,0,0,0,0,0,0,0,0 } },
  { 7,     "MB",       0, { 0,0,0,0,0,0,0,0,0,0 } },
  { 8,     "MG",       0, { 0,0,0,0,0,0,0,0,0,0 } },
  { 9,     "MR",       0, { 0,0,0,0,0,0,0,0,0,0 } },
  { 10,    "NULL",     0, { 0,0,0,0,0,0,0,0,0,0 } },
  { 11,    "WKS",      0, { 0,0,0,0,0,0,0,0,0,0 } },
  { 12,    "PTR",      0, { 0,0,0,0,0,0,0,0,0,0 } },
  { 13,    "HINFO",    0, { 0,0,0,0,0,0,0,0,0,0 } },
  { 14,    "MINFO",    0, { 0,0,0,0,0,0,0,0,0,0 } },
  { 15,    "MX",       0, { 0,0,0,0,0,0,0,0,0,0 } },
  { 16,    "TXT",      0, { 0,0,0,0,0,0,0,0,0,0 } },
  { 17,    "RP",       0, { 0,0,0,0,0,0,0,0,0,0 } },
  { 18,    "AFSDB",    0, { 0,0,0,0,0,0,0,0,0,0 } },
  { 19,    "X25",      0, { 0,0,0,0,0,0,0,0,0,0 } },
  { 20,    "ISDN",     0, { 0,0,0,0,0,0,0,0,0,0 } },
  { 21,    "RT",       0, { 0,0,0,0,0,0,0,0,0,0 } },
  { 22,    "NSAP",     0, { 0,0,0,0,0,0,0,0,0,0 } },
  { 23,    "NSAP-PTR", 0, { 0,0,0,0,0,0,0,0,0,0 } },
  { 24,    "SIG",      0, { 0,0,0,0,0,0,0,0,0,0 } },
  { 25,    "KEY",      0, { 0,0,0,0,0,0,0,0,0,0 } },
  { 26,    "PX",       0, { 0,0,0,0,0,0,0,0,0,0 } },
  { 27,    "GPOS",     0, { 0,0,0,0,0,0,0,0,0,0 } },
  { 28,    "AAAA",     0, { 0,0,0,0,0,0,0,0,0,0 } },
  { 29,    "LOC",      0, { 0,0,0,0,0,0,0,0,0,0 } },
  { 30,    "NXT",      0, { 0,0,0,0,0,0,0,0,0,0 } },
  { 31,    "EID",      0, { 0,0,0,0,0,0,0,0,0,0 } },
  { 32,    "NIMLOC",   0, { 0,0,0,0,0,0,0,0,0,0 } },
  { 33,    "SRV",      0, { 0,0,0,0,0,0,0,0,0,0 } },
  { 34,    "ATMA",     0, { 0,0,0,0,0,0,0,0,0,0 } },
  { 35,    "NAPTR",    0, { 0,0,0,0,0,0,0,0,0,0 } },
  { 36,    "KX",       0, { 0,0,0,0,0,0,0,0,0,0 } },
  { 37,    "CERT",     0, { 0,0,0,0,0,0,0,0,0,0 } },
  { 38,    "A6",       0, { 0,0,0,0,0,0,0,0,0,0 } },
  { 39,    "DNAME",    0, { 0,0,0,0,0,0,0,0,0,0 } },
  { 40,    "SINK",     0, { 0,0,0,0,0,0,0,0,0,0 } },
  { 41,    "OPT",      0, { 0,0,0,0,0,0,0,0,0,0 } },
  { 42,    "APL",      0, { 0,0,0,0,0,0,0,0,0,0 } },
  { 43,    "DS",       0, { 0,0,0,0,0,0,0,0,0,0 } },
  { 44,    "SSHFP",    0, { 0,0,0,0,0,0,0,0,0,0 } },
  { 45,    "IPSECKEY", 0, { 0,0,0,0,0,0,0,0,0,0 } },
  { 46,    "RRSIG",    0, { 0,0,0,0,0,0,0,0,0,0 } },
  { 47,    "NSEC",     0, { 0,0,0,0,0,0,0,0,0,0 } },
  { 48,    "DNSKEY",   0, { 0,0,0,0,0,0,0,0,0,0 } },
  { 49,    "DHCID",    0, { 0,0,0,0,0,0,0,0,0,0 } },
  { 50,    "NSEC3",    0, { 0,0,0,0,0,0,0,0,0,0 } },
  { 51,    "NSEC3PARAM",0,{ 0,0,0,0,0,0,0,0,0,0 } },
  { 52,    "TLSA",     0, { 0,0,0,0,0,0,0,0,0,0 } },
  { 53,    "SMIMEA",   0, { 0,0,0,0,0,0,0,0,0,0 } },

  { 55,    "HIP",      0, { 0,0,0,0,0,0,0,0,0,0 } },
  { 56,    "NINFO",    0, { 0,0,0,0,0,0,0,0,0,0 } },
  { 57,    "RKEY",     0, { 0,0,0,0,0,0,0,0,0,0 } },
  { 58,    "TALINK",   0, { 0,0,0,0,0,0,0,0,0,0 } },
  { 59,    "CDS",      0, { 0,0,0,0,0,0,0,0,0,0 } },
  { 60,    "CDNSKEY",  0, { 0,0,0,0,0,0,0,0,0,0 } },
  { 61,    "OPENPGPKEY",0,{ 0,0,0,0,0,0,0,0,0,0 } },
  { 62,    "CSYNC",    0, { 0,0,0,0,0,0,0,0,0,0 } },
  { 63,    "ZONEMD",   0, { 0,0,0,0,0,0,0,0,0,0 } },
  { 64,    "SVCB",     0, { 0,0,0,0,0,0,0,0,0,0 } },
  { 65,    "HTTPS",    0, { 0,0,0,0,0,0,0,0,0,0 } },
  { 66,    "DSYNC",    0, { 0,0,0,0,0,0,0,0,0,0 } },
  { 67,    "HHIT",     0, { 0,0,0,0,0,0,0,0,0,0 } },
  { 68,    "BRID",     0, { 0,0,0,0,0,0,0,0,0,0 } },

  { 99,    "SPF",      0, { 0,0,0,0,0,0,0,0,0,0 } },
  { 100,   "UINFO",    0, { 0,0,0,0,0,0,0,0,0,0 } },
  { 101,   "UID",      0, { 0,0,0,0,0,0,0,0,0,0 } },
  { 102,   "GID",      0, { 0,0,0,0,0,0,0,0,0,0 } },
  { 103,   "UNSPEC",   0, { 0,0,0,0,0,0,0,0,0,0 } },

  { 104,   "NID",      0, { 0,0,0,0,0,0,0,0,0,0 } },
  { 105,   "L32",      0, { 0,0,0,0,0,0,0,0,0,0 } },
  { 106,   "L64",      0, { 0,0,0,0,0,0,0,0,0,0 } },
  { 107,   "LP",       0, { 0,0,0,0,0,0,0,0,0,0 } },

  { 108,   "EUI48",    0, { 0,0,0,0,0,0,0,0,0,0 } },
  { 109,   "EUI64",    0, { 0,0,0,0,0,0,0,0,0,0 } },

  { 128,   "NXNAME",   0, { 0,0,0,0,0,0,0,0,0,0 } },

  { 249,   "TKEY",     0, { 0,0,0,0,0,0,0,0,0,0 } },
  { 250,   "TSIG",     0, { 0,0,0,0,0,0,0,0,0,0 } },
  { 251,   "IXFR",     0, { 0,0,0,0,0,0,0,0,0,0 } },
  { 252,   "AXFR",     0, { 0,0,0,0,0,0,0,0,0,0 } },
  { 253,   "MAILB",    0, { 0,0,0,0,0,0,0,0,0,0 } },
  { 254,   "MAILA",    0, { 0,0,0,0,0,0,0,0,0,0 } },
  { 255,   "*",        0, { 0,0,0,0,0,0,0,0,0,0 } },

  { 256,   "URI",      0, { 0,0,0,0,0,0,0,0,0,0 } },
  { 257,   "CAA",      0, { 0,0,0,0,0,0,0,0,0,0 } },
  { 258,   "AVC",      0, { 0,0,0,0,0,0,0,0,0,0 } },
  { 259,   "DOA",      0, { 0,0,0,0,0,0,0,0,0,0 } },
  { 260,   "AMTRELAY", 0, { 0,0,0,0,0,0,0,0,0,0 } },
  { 261,   "RESINFO",  0, { 0,0,0,0,0,0,0,0,0,0 } },
  { 262,   "WALLET",   0, { 0,0,0,0,0,0,0,0,0,0 } },
  { 263,   "CLA",      0, { 0,0,0,0,0,0,0,0,0,0 } },
  { 264,   "IPN",      0, { 0,0,0,0,0,0,0,0,0,0 } },

  { 32768,"TA",        0, { 0,0,0,0,0,0,0,0,0,0 } },
  { 32769,"DLV",       0, { 0,0,0,0,0,0,0,0,0,0 } },
};

static const size_t g_rrtypes_count = sizeof(g_rrtypes) / sizeof(g_rrtypes[0]);

// -----------------------------------------------------------------------------
// Two hash tables:
//  1) name -> index in g_rrtypes
//  2) type value -> index in g_rrtypes
// -----------------------------------------------------------------------------

#ifndef ZONE_RRTYPE_NAME_HT_SIZE
#define ZONE_RRTYPE_NAME_HT_SIZE 256u
#endif

#ifndef ZONE_RRTYPE_NUM_HT_SIZE
#define ZONE_RRTYPE_NUM_HT_SIZE 256u
#endif

static uint16_t g_name_ht[ZONE_RRTYPE_NAME_HT_SIZE];
static uint16_t g_num_ht[ZONE_RRTYPE_NUM_HT_SIZE];
static int g_ht_inited = 0;

static void ht_init_once(void) {
  if (g_ht_inited) return;

  for (size_t i = 0; i < ZONE_RRTYPE_NAME_HT_SIZE; i++) g_name_ht[i] = 0xFFFFu;
  for (size_t i = 0; i < ZONE_RRTYPE_NUM_HT_SIZE; i++)  g_num_ht[i]  = 0xFFFFu;

  // Build name hash
  for (uint16_t i = 0; i < (uint16_t)g_rrtypes_count; i++) {
    const char *name = g_rrtypes[i].name_caps;
    size_t len = strlen(name);
    uint32_t h = fnv1a_u32_ascii_upper(name, len);

#if (ZONE_RRTYPE_NAME_HT_SIZE & (ZONE_RRTYPE_NAME_HT_SIZE - 1u)) == 0
    uint32_t pos = h & (ZONE_RRTYPE_NAME_HT_SIZE - 1u);
#else
    uint32_t pos = h % ZONE_RRTYPE_NAME_HT_SIZE;
#endif

    for (;;) {
      if (g_name_ht[pos] == 0xFFFFu) { g_name_ht[pos] = i; break; }
      pos++; if (pos == ZONE_RRTYPE_NAME_HT_SIZE) pos = 0;
    }
  }

  // Build numeric hash
  for (uint16_t i = 0; i < (uint16_t)g_rrtypes_count; i++) {
    uint16_t val = g_rrtypes[i].value;
    uint32_t h = fnv1a_u32_u16(val);

#if (ZONE_RRTYPE_NUM_HT_SIZE & (ZONE_RRTYPE_NUM_HT_SIZE - 1u)) == 0
    uint32_t pos = h & (ZONE_RRTYPE_NUM_HT_SIZE - 1u);
#else
    uint32_t pos = h % ZONE_RRTYPE_NUM_HT_SIZE;
#endif

    for (;;) {
      if (g_num_ht[pos] == 0xFFFFu) { g_num_ht[pos] = i; break; }
      pos++; if (pos == ZONE_RRTYPE_NUM_HT_SIZE) pos = 0;
    }
  }

  g_ht_inited = 1;
}

static const struct rrtype_t *lookup_by_name(const char *s, size_t s_len) {
  uint32_t h = fnv1a_u32_ascii_upper(s, s_len);

#if (ZONE_RRTYPE_NAME_HT_SIZE & (ZONE_RRTYPE_NAME_HT_SIZE - 1u)) == 0
  uint32_t pos = h & (ZONE_RRTYPE_NAME_HT_SIZE - 1u);
#else
  uint32_t pos = h % ZONE_RRTYPE_NAME_HT_SIZE;
#endif

  for (uint32_t probes = 0; probes < ZONE_RRTYPE_NAME_HT_SIZE; probes++) {
    uint16_t idx = g_name_ht[pos];
    if (idx == 0xFFFFu) return 0;

    const struct rrtype_t *rt = &g_rrtypes[idx];
    if (ascii_ieq_n(s, s_len, rt->name_caps)) return rt;

    pos++; if (pos == ZONE_RRTYPE_NAME_HT_SIZE) pos = 0;
  }

  return 0;
}

static const struct rrtype_t *lookup_by_value(uint16_t v) {
  uint32_t h = fnv1a_u32_u16(v);

#if (ZONE_RRTYPE_NUM_HT_SIZE & (ZONE_RRTYPE_NUM_HT_SIZE - 1u)) == 0
  uint32_t pos = h & (ZONE_RRTYPE_NUM_HT_SIZE - 1u);
#else
  uint32_t pos = h % ZONE_RRTYPE_NUM_HT_SIZE;
#endif

  for (uint32_t probes = 0; probes < ZONE_RRTYPE_NUM_HT_SIZE; probes++) {
    uint16_t idx = g_num_ht[pos];
    if (idx == 0xFFFFu) return 0;

    const struct rrtype_t *rt = &g_rrtypes[idx];
    if (rt->value == v) return rt;

    pos++; if (pos == ZONE_RRTYPE_NUM_HT_SIZE) pos = 0;
  }

  return 0;
}

// -----------------------------------------------------------------------------
// TYPE#### parsing
// -----------------------------------------------------------------------------

static int parse_TYPE_decimal(const char *s, size_t n, uint16_t *out_val) {
  if (!s || !out_val) return 0;
  if (n < 5) return 0;

  if (!(ascii_upper((uint8_t)s[0]) == 'T' &&
        ascii_upper((uint8_t)s[1]) == 'Y' &&
        ascii_upper((uint8_t)s[2]) == 'P' &&
        ascii_upper((uint8_t)s[3]) == 'E')) {
    return 0;
  }

  size_t i = 4;
  if (i >= n) return 0;
  if (s[i] < '0' || s[i] > '9') return 0;

  uint32_t v = 0;
  for (; i < n; i++) {
    char c = s[i];
    if (c < '0' || c > '9') return 0;
    v = v * 10u + (uint32_t)(c - '0');
    if (v > 65535u) return 0;
  }

  *out_val = (uint16_t)v;
  return 1;
}

// -----------------------------------------------------------------------------
// Public lookup
// -----------------------------------------------------------------------------

int zone_rrtype_lookup(const char *s, size_t s_len, const struct rrtype_t **out) {
  if (!out) return -2;
  *out = 0;
  if (!s || s_len == 0) return -2;

  ht_init_once();

  // 1) Normal mnemonic lookup by name
  {
    const struct rrtype_t *rt = lookup_by_name(s, s_len);
    if (rt) { *out = rt; return 0; }
  }

  // 2) TYPE#### handling
  uint16_t v = 0;
  if (parse_TYPE_decimal(s, s_len, &v)) {
    // If the numeric value is known, return that entry (so you can later attach
    // a parser/formatter and it will get picked up even via TYPE####).
    const struct rrtype_t *rt_num = lookup_by_value(v);
    if (rt_num) { *out = rt_num; return 0; }

    // Otherwise return a generic rrtype:
    // - value set to the parsed numeric type
    // - name_caps set to 0
    // - formatter/parsers set for "\# <len> <hex>" form.
#if defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 201112L) && !defined(__STDC_NO_THREADS__)
    static _Thread_local struct rrtype g_generic;
#else
    static struct rrtype_t g_generic;
#endif

    g_generic.value = v;
    g_generic.name_caps = 0;
    g_generic.format = rrdata_format_generic_hash;

    // Put the generic "\#" parser in slot 0, others 0.
    g_generic.parsers[0] = rrdata_parse_generic_hash;
    for (size_t i = 1; i < ZONE_RRTYPE_PARSER_MAX; i++) g_generic.parsers[i] = 0;

    *out = &g_generic;
    return 0;
  }

  return -1;
}
