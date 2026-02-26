
#include "zone-atom.h"
#include "zone-parse.h"
#include "zone-parse-record.h"
#include "zone-error.h"
/* zone-atom-svcparams.c
 *
 * RFC 9460 SvcParams parser for SVCB/HTTPS RDATA.
 *
 * Wire encoding emitted by this atom:
 *   Repeated:
 *     SvcParamKey      (uint16)
 *     SvcParamValueLen (uint16)
 *     SvcParamValue    (bytes)
 *
 * Presentation parsing supported:
 *   - mandatory=key1,key2,keyNNNN
 *   - alpn="h2,h3"  (also accepts unquoted token h2,h3)
 *   - no-default-alpn   (bare key, no value)
 *   - port=443
 *   - ipv4hint=192.0.2.1,198.51.100.2
 *   - ipv6hint=2001:db8::1,2001:db8::2
 *   - ech=... (parsed as token/quoted string with escapes; bytes copied verbatim)
 *   - dohpath=/dns-query{?dns} (same)
 *   - ohttp=... (same)
 *
 * Stop conditions:
 *   - Stops before ';' '\r' '\n' '(' ')' or max
 *   - Uses zone_parse_space() between params (needs unsigned *depth)
 *
 * Error style (matching your int16 atom):
 *   - If cursor > max: return max+1
 *   - Set out->err_code=1 and out->err_cursor once on error
 *
 * Assumed helpers:
 *   size_t zone_parse_space(const char *data, size_t cursor, size_t max,
 *                           struct wire_record_t *out, unsigned *depth);
 *   void wire_append_uint16(struct wire_record_t *out, uint16_t v, int *err);
 *   void wire_append_uint8 (struct wire_record_t *out, uint8_t  v, int *err);
 *   void wire_append_bytes(struct wire_record_t *out, const void *p, size_t n, int *err);
 *
 * Also assumed you already have atom IPv4/IPv6 parsers:
 *   size_t zone_atom_ipv4(const char *data, size_t cursor, size_t max, struct wire_record_t *out);
 *   size_t zone_atom_ipv6(const char *data, size_t cursor, size_t max, struct wire_record_t *out);
 *
 * IMPORTANT: This file uses a local “scratch wire_record_t” to reuse zone_atom_ipv4/ipv6
 * to write into a temporary value buffer. That requires your wire_record_t to contain:
 *   wire (uint8_t*), wire_offset (size_t), wire_max (size_t), err_code, err_cursor
 * If your layout differs, replace svc_write_ipv4/ipv6() with direct parsers.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>





static int is_digit(char c) {
    return c >= '0' && c <= '9';
}

static int is_space_equiv(char c)
{
    return c == ' '  || c == '\t' ||
           c == '\r' || c == '\n' ||
           c == ';'  || c == '('  || c == ')';
}

#if 0
static int is_key_char(char c)
{
    /* RFC 9460 keys are lowercase in registry; accept conservative superset */
    if (c >= 'a' && c <= 'z') return 1;
    if (c >= '0' && c <= '9') return 1;
    if (c == '-') return 1;
    return 0;
}
#endif

/*
 * find_key_length(data, cursor, max)
 *
 * Scans forward from data+cursor until it finds either:
 *     '='  (0x3D)
 *     '\n' (0x0A)
 *
 * Returns the number of bytes before that character.
 *
 * Assumptions:
 *   - There is guaranteed to be at least one '=' or '\n'
 *   - At least 64 bytes of readable padding past the terminator
 *   - max is unused
 *
 * Uses SWAR 8-byte scanning.
 */
static inline size_t
find_key_length(const char *data, size_t cursor, size_t max)
{
    (void)max; /* unused */

    const unsigned char *p = (const unsigned char *)data + cursor;

    const uint64_t eq_mask = 0x3D3D3D3D3D3D3D3DULL; /* '=' */
    const uint64_t nl_mask = 0x0A0A0A0A0A0A0A0AULL; /* '\n' */
    const uint64_t high_bits = 0x8080808080808080ULL;

    size_t offset = 0;

    for (;;) {
        uint64_t chunk;

        /* unaligned load is fine on x86/ARM64 */
        __builtin_memcpy(&chunk, p + offset, sizeof(chunk));

        uint64_t x_eq = chunk ^ eq_mask;
        uint64_t x_nl = chunk ^ nl_mask;

        /* detect zero bytes in each */
        uint64_t m_eq =
            (x_eq - 0x0101010101010101ULL) &
            ~x_eq &
            high_bits;

        uint64_t m_nl =
            (x_nl - 0x0101010101010101ULL) &
            ~x_nl &
            high_bits;

        uint64_t m = m_eq | m_nl;

        if (m) {
            /* first matching byte */
            unsigned bit_index = __builtin_ctzll(m);
            unsigned byte_index = bit_index >> 3;
            return offset + byte_index;
        }

        offset += 8;
    }
}


//static uint16_t read_u16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static void write_u16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)(v & 0xFF); }

static int parse_uint16_dec(const char *data, size_t *pcursor, size_t max, uint16_t *outv)
{
    size_t cursor = *pcursor;
    uint32_t v = 0;
    int saw = 0;
    while (cursor < max && is_digit(data[cursor])) {
        saw = 1;
        v = v * 10u + (uint32_t)(data[cursor] - '0');
        if (v > 65535u) return 0;
        cursor++;
    }
    if (!saw) return 0;
    *pcursor = cursor;
    *outv = (uint16_t)v;
    return 1;
}

/* parse \DDD (3 decimal digits) */
/*static int parse_ddd_byte(const char *data, size_t cursor, size_t max, uint8_t *outb)
{
    if (cursor + 2 >= max) return 0;
    char a = data[cursor], b = data[cursor+1], c = data[cursor+2];
    if (!is_digit(a) || !is_digit(b) || !is_digit(c)) return 0;
    unsigned v = (unsigned)(a-'0')*100u + (unsigned)(b-'0')*10u + (unsigned)(c-'0');
    if (v > 255u) return 0;
    *outb = (uint8_t)v;
    return 1;
}*/
/* Returns bytes consumed (>=2) starting at data[i] where data[i] == '\\'.
   On error returns 0. */
static size_t
parse_escape(const char *data, size_t i, size_t max, uint8_t *out_byte)
{
    if (i >= max) return 0;
    if ((unsigned char)data[i] != (unsigned char)'\\') return 0;

    /* Need at least one character after '\' */
    if (i + 1 >= max) return 0;

    unsigned char c1 = (unsigned char)data[i + 1];

    /* \DDD : exactly three decimal digits */
    if (i + 3 < max &&
        is_digit(c1) &&
        is_digit((unsigned char)data[i + 2]) &&
        is_digit((unsigned char)data[i + 3]))
    {
        unsigned d1 = (unsigned)(data[i + 1] - '0');
        unsigned d2 = (unsigned)(data[i + 2] - '0');
        unsigned d3 = (unsigned)(data[i + 3] - '0');

        unsigned val = d1 * 100u + d2 * 10u + d3;

        if (val > 255u) return 0;

        *out_byte = (uint8_t)val;
        return 4; /* '\'+3 digits */
    }

    /* \X : literal next char */
    *out_byte = (uint8_t)c1;
    return 2;
}

/* Parse token or quoted string into dst (no leading length); supports escapes like zone_atom_txt */
static size_t parse_stringish(const char *data, size_t cursor, size_t max,
                              uint8_t *dst, size_t dst_max, size_t *out_len,
                              struct wire_record_t *out)
{
    size_t len = 0;

    if (cursor >= max)
        return cursor;
    
    if (data[cursor] == '"') {
        cursor++;
        for (;;) {
            if (cursor >= max)
                return cursor;

            char c = data[cursor];
            if (c == '"') {
                cursor++;
                break;
            }

            if (c == '\\') {
                uint8_t v;
                cursor = parse_escape(data, cursor, max, &v);
                if (len < dst_max)
                    dst[len++] = v;
                else
                    PARSE_ERR(1, cursor, max, out);
                continue;
            }

            if (len < dst_max)
                dst[len++] = (uint8_t)c;
            else
                PARSE_ERR(1, cursor, max, out);
            cursor++;
        }
    } else {
        for (;;) {
            if (cursor > max) return max + 1;
            if (cursor == max) break;
            char c = data[cursor];
            if (is_space_equiv(c)) break;

            if (c == '\\') {
                uint8_t v;
                cursor = parse_escape(data, cursor, max, &v);
                if (len < dst_max)
                    dst[len++] = v;
                else
                    PARSE_ERR(1, cursor, max, out);
                continue;
            }
 
            if (len < dst_max)
                dst[len++] = (uint8_t)(unsigned char)c;
            else
                PARSE_ERR(1, cursor, max, out);
            cursor++;
        }
    }

    *out_len = len;
    return cursor;
}

/* Key name -> SvcParamKey number (IANA / RFC9460 well-known set; unknown supports keyNNNN). */
static int svc_key_from_name(const char *name, size_t length, uint16_t *out_key) {
    /* RFC 9460 core */
    if (length == 9  && memcmp(name, "mandatory", 9) == 0)      { *out_key = 0; return 1; }
    if (length == 4  && memcmp(name, "alpn", 4) == 0)           { *out_key = 1; return 1; }
    if (length == 15 && memcmp(name, "no-default-alpn", 15) == 0){ *out_key = 2; return 1; }
    if (length == 4  && memcmp(name, "port", 4) == 0)           { *out_key = 3; return 1; }
    if (length == 8  && memcmp(name, "ipv4hint", 8) == 0)       { *out_key = 4; return 1; }
    if (length == 3  && memcmp(name, "ech", 3) == 0)            { *out_key = 5; return 1; }
    if (length == 8  && memcmp(name, "ipv6hint", 8) == 0)       { *out_key = 6; return 1; }

    /* commonly deployed extras in IANA registry (post-RFC9460 additions) */
    if (length == 6  && memcmp(name, "dohpath", 7) == 0)        { /* unreachable: n mismatch */ }
    if (length == 7  && memcmp(name, "dohpath", 7) == 0)        { *out_key = 7; return 1; }
    if (length == 5  && memcmp(name, "ohttp", 5) == 0)          { *out_key = 8; return 1; }

    /* keyNNNN */
    if (length >= 4 && memcmp(name, "key", 3) == 0) {
        uint32_t v = 0;
        size_t i;
        for (i = 3; i < length; i++) {
            if (name[i] < '0' || name[i] > '9') return 0;
            v = v * 10u + (uint32_t)(name[i] - '0');
            if (v > 65535u) return 0;
        }
        *out_key = (uint16_t)v;
        return 1;
    }

    return 0;
}

/* Parse comma-separated list of key names into u16 vector (network order) */
static size_t parse_mandatory_list(const char *data, size_t cursor, size_t max,
                                   uint8_t *dst, size_t dst_max, size_t *out_len,
                                   struct wire_record_t *out)
{
    size_t len = 0;
    for (;;) {
        uint8_t namebuf[256];
        size_t namelen = 0;

        /* name token until comma or space-equivalent */
        while (cursor < max) {
            char c = data[cursor];
            if (c == ',' || is_space_equiv(c)) break;
            if (namelen < sizeof(namebuf)) namebuf[namelen++] = (uint8_t)(unsigned char)c;
            cursor++;
        }
        if (namelen == 0) {
            PARSE_ERR(1, cursor, max, out);
            break;
        }

        uint16_t keynum = 0;
        if (!svc_key_from_name((const char *)namebuf, namelen, &keynum)) {
            PARSE_ERR(1, cursor, max, out);
        }

        if (len + 2 <= dst_max) {
            write_u16(dst + len, keynum);
            len += 2;
        } else {
            PARSE_ERR(1, cursor, max, out);
        }

        if (cursor >= max) break;
        if (data[cursor] == ',') { cursor++; continue; }
        break;
    }

    *out_len = len;
    return cursor;
}

/* Parse alpn value "h2,h3" or h2,h3 into ALPN vector: [len][id]... */
static size_t parse_alpn_list(const char *data, size_t cursor, size_t max,
                              uint8_t *dst, size_t dst_max, size_t *out_len,
                              struct wire_record_t *out)
{
    uint8_t tmp[1024];
    size_t tlen = 0;

    cursor = parse_stringish(data, cursor, max, tmp, sizeof(tmp), &tlen, out);
    if (cursor > max) { *out_len = 0; return cursor; }

    size_t len = 0;
    size_t i = 0;
    while (i <= tlen) {
        size_t start = i;
        while (i < tlen && tmp[i] != ',') i++;
        size_t n = i - start;

        if (n > 255u)
            PARSE_ERR(1, cursor, max, out);
        if (len + 1 + n <= dst_max) {
            dst[len++] = (uint8_t)n;
            if (n) memcpy(dst + len, tmp + start, n);
            len += n;
        } else {
            PARSE_ERR(1, cursor, max, out);
        }

        if (i >= tlen) break;
        i++; /* skip comma */
    }

    *out_len = len;
    return cursor;
}

/* Use your existing IPv4/IPv6 atom parsers to encode into dst via scratch wire_record_t */
static size_t svc_write_ipv4_list(const char *data, size_t cursor, size_t max,
                                  uint8_t *dst, size_t dst_max, size_t *out_len,
                                  struct wire_record_t *out)
{
    wire_record_t out2 = {0};
    out2.wire.buf = dst;
    out2.wire.max = dst_max;
    
    /* parse addr[,addr]*; commas are separators */
    for (;;) {
        cursor = zone_atom_ipv4(data, cursor, max, &out2);
        if (cursor > max)
            break;
        if (cursor >= max)
            break;
        if (data[cursor] == ',') {
            cursor++;
            continue;
        }
        break;
    }
    *out_len = out2.wire.len;
    if (out2.err.code && !out->err.code) {
        out->err.code = out2.err.code;
        out->err.cursor = out2.err.cursor;
    }

    return cursor;
}

static size_t svc_write_ipv6_list(const char *data, size_t cursor, size_t max,
                                  uint8_t *dst, size_t dst_max, size_t *out_len,
                                  struct wire_record_t *out)
{
    wire_record_t out2 = {0};
    out2.wire.buf = dst;
    out2.wire.max = dst_max;

    for (;;) {
        cursor = zone_atom_ipv6(data, cursor, max, &out2);
        if (cursor > max) break;
        if (cursor >= max) break;
        if (data[cursor] == ',') { cursor++; continue; }
        break;
    }
    
    *out_len = out2.wire.len;
    if (out2.err.code && !out->err.code) {
        out->err.code = out2.err.code;
        out->err.cursor = out2.err.cursor;
    }
    return cursor;
}

struct svc_param_tmp {
    uint16_t key;
    uint16_t vlen;
    uint16_t voff; /* offset into vblob */
};

/* qsort comparator */
static int svc_param_cmp(const void *a, const void *b)
{
    const struct svc_param_tmp *A = (const struct svc_param_tmp *)a;
    const struct svc_param_tmp *B = (const struct svc_param_tmp *)b;
    return (A->key > B->key) - (A->key < B->key);
}

extern void qsort(void *base, size_t nmemb, size_t size, int (*compar)(const void*, const void*));

size_t
zone_atom_svcparams(const char *data, size_t cursor, size_t max,
                    struct wire_record_t *out, unsigned *depth)
{
    /* limits to keep stack bounded; adjust to taste */
    struct svc_param_tmp params[64];
    size_t pcount = 0;

    uint8_t vblob[4096];
    size_t vblob_len = 0;

    if (cursor > max)
        return max + 1;

    for (;;) {
        if (is_space_equiv(data[cursor]))
            cursor = zone_parse_space(data, cursor, max, out, depth);
        if (cursor > max)
            return max + 1;
        if (cursor == max)
            break;

        /* end-of-record markers */
        if (is_space_equiv(data[cursor]))
            break;

        /*
         * parse key token
         */
        const char *keybuf = data + cursor;
        size_t keylen = find_key_length(data, cursor, max);
        uint16_t keynum = 0;
        if (!svc_key_from_name(keybuf, keylen, &keynum)) {
            /* unknown bare key name: error but keep parsing */
            PARSE_ERR(1, cursor, max, out);
            
            /* map unknown to keyNNNN is unsupported without "key123"; treat as 65535? */
            keynum = 65535u;
        }
        cursor += keylen;

        /*
         * determine value bytes
         */
        uint8_t vtmp[1024];
        size_t vlen = 0;
        if (data[cursor] == '=') {
            cursor++; /* consume '=' */

            switch (keynum) {
            case 0:
                cursor = parse_mandatory_list(data, cursor, max, vtmp, sizeof(vtmp), &vlen, out);
                break;
            case 1: /* "alpn" */
                cursor = parse_alpn_list(data, cursor, max, vtmp, sizeof(vtmp), &vlen, out);
                break;
            case 3: {
                size_t c2 = cursor;
                uint16_t port = 0;
                if (!parse_uint16_dec(data, &c2, max, &port)) {
                    PARSE_ERR(1, cursor, max, out);
                }
                vtmp[0] = (uint8_t)(port >> 8);
                vtmp[1] = (uint8_t)(port & 0xFF);
                vlen = 2;
                cursor = c2;
                }
                break;
            case 4:
                cursor = svc_write_ipv4_list(data, cursor, max, vtmp, sizeof(vtmp), &vlen, out);
                break;
            case 6:
                cursor = svc_write_ipv6_list(data, cursor, max, vtmp, sizeof(vtmp), &vlen, out);
                break;
            default:
                /* ech / dohpath / ohttp / unknown: copy token/quoted string bytes */
                cursor = parse_stringish(data, cursor, max, vtmp, sizeof(vtmp), &vlen, out);
                break;
            }
        } else {
            /* bare key */
            vlen = 0;

            /* RFC 9460: no-default-alpn must be bare; others bare are allowed for unknown keys */
            if (keynum != 2 && keynum != 65535u) {
                /* tolerate but mark error for keys that normally need a value */
                if (keynum == 0 || keynum == 1 || keynum == 3 || keynum == 4 || keynum == 6 || keynum == 5)
                    PARSE_ERR(1, cursor, max, out);
            }
        }

        /* store param (buffer value into vblob) */
        if (pcount < (sizeof(params)/sizeof(params[0])) && vblob_len + vlen <= sizeof(vblob)) {
            params[pcount].key  = keynum;
            params[pcount].vlen = (uint16_t)(vlen > 65535u ? 65535u : vlen);
            params[pcount].voff = (uint16_t)vblob_len;
            if (vlen) memcpy(vblob + vblob_len, vtmp, vlen);
            vblob_len += vlen;
            pcount++;
        } else {
            PARSE_ERR(1, cursor, max, out);
        }

        /* continue loop */
    }

    /* sort by key */
    if (pcount > 1)
        qsort(params, pcount, sizeof(params[0]), svc_param_cmp);

    /* emit wire */
    {
        size_t i;
        for (i = 0; i < pcount; i++) {
            wire_append_uint16(out, params[i].key);
            wire_append_uint16(out, params[i].vlen);
            if (params[i].vlen) {
                const uint8_t *p = vblob + params[i].voff;
                wire_append_bytes(out, p, params[i].vlen);
            }
        }
    }

    /* keep moving forward after params */
    cursor = zone_parse_space(data, cursor, max, out, depth);
    return cursor;
}
