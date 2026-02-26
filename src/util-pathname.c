/* util-pathname.c */

#include "util-pathname.h"

#include <string.h>
#include <stdio.h>
#include <ctype.h>

static void util_seterr(char *err, size_t errsz, const char *msg) {
    if (!err || errsz == 0) return;
    snprintf(err, errsz, "%s", msg);
}

static int util_is_sep(char c) { return c == '/' || c == '\\'; }
static int util_is_ctl_or_del(unsigned char c) { return (c < 0x20) || (c == 0x7f); }

static int util_has_drive_prefix(const char *p) {
    return p && isalpha((unsigned char)p[0]) && p[1] == ':';
}

/* Most-conservative per-segment allowlist. */
static int util_is_allowed_seg_char(unsigned char c) {
    if (c >= 'a' && c <= 'z') return 1;
    if (c >= 'A' && c <= 'Z') return 1;
    if (c >= '0' && c <= '9') return 1;
    if (c == '.' || c == '_' || c == '-') return 1;
    return 0;
}

/* Determine whether a path is absolute.
   - POSIX absolute: "/x"
   - Windows absolute: "C:\x" or "C:/x" or "\x"
   - UNC: "\\server\share" (absolute-ish, but rejected by policy) */
static int util_is_absolute_path(const char *p, int *is_unc_out) {
    if (is_unc_out) *is_unc_out = 0;
    if (!p || !*p) return 0;

    if (p[0] == '\\' && p[1] == '\\') {
        if (is_unc_out) *is_unc_out = 1;
        return 1;
    }

    if (p[0] == '/' || p[0] == '\\') return 1;

    if (util_has_drive_prefix(p)) {
        /* Treat as absolute only if "C:\..." or "C:/..." */
        if (util_is_sep(p[2])) return 1;
        return 0;
    }

    return 0;
}

/* Normalize separators to '/', reject control chars globally. */
static enum util_path_rc
util_validate_and_normalize_seps(char *dst, size_t dstsz,
                                 const char *src,
                                 char *err, size_t errsz)
{
    if (!dst || dstsz == 0 || !src) {
        util_seterr(err, errsz, "invalid arguments");
        return UTIL_PATH_EINVAL;
    }
    size_t n = strlen(src);
    if (n + 1 > dstsz) {
        util_seterr(err, errsz, "path too long");
        return UTIL_PATH_ETOOLONG;
    }
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)src[i];
        if (util_is_ctl_or_del(c)) {
            util_seterr(err, errsz, "path contains control characters");
            return UTIL_PATH_ECHAR;
        }
        dst[i] = util_is_sep((char)c) ? '/' : (char)c;
    }
    dst[n] = '\0';
    return UTIL_PATH_OK;
}

/* Extract dirname(curfile) into dirbuf (normalized), keeping trailing '/' if non-empty. */
static enum util_path_rc
util_dirname(char *dirbuf, size_t dirsz, const char *curfile,
             char *err, size_t errsz)
{
    enum util_path_rc rc = util_validate_and_normalize_seps(dirbuf, dirsz, curfile, err, errsz);
    if (rc != UTIL_PATH_OK) return rc;

    char *last = strrchr(dirbuf, '/');
    if (!last) {
        dirbuf[0] = '\0'; /* current directory */
        return UTIL_PATH_OK;
    }
    last[1] = '\0'; /* keep trailing '/' */
    return UTIL_PATH_OK;
}

struct util_seg { const char *p; size_t len; };

enum util_path_rc
util_path_resolve_from_file_dir(char *out, size_t outsz,
                                const char *curfile,
                                const char *input_path,
                                int *is_absolute_out,
                                char *err, size_t errsz)
{
    if (!out || outsz == 0 || !curfile || !input_path || !is_absolute_out) {
        util_seterr(err, errsz, "invalid arguments");
        return UTIL_PATH_EINVAL;
    }

    int is_unc = 0;
    int is_abs = util_is_absolute_path(input_path, &is_unc);
    *is_absolute_out = is_abs;

    if (is_unc) {
        util_seterr(err, errsz, "UNC paths are rejected");
        return UTIL_PATH_EUNC;
    }

    /* Normalize the input path separators to '/', reject control chars */
    char in_norm[4096];
    enum util_path_rc rc = util_validate_and_normalize_seps(in_norm, sizeof(in_norm),
                                                            input_path, err, errsz);
    if (rc != UTIL_PATH_OK) return rc;

    /* Segment stack */
    struct util_seg segs[512];
    size_t seg_count = 0;

    /* Preserve drive prefix "C:" if present (from absolute input OR from curfile base). */
    char drive_prefix[3] = {0,0,0};
    size_t drive_len = 0;

    /* Base/rootness of the output. For relative inputs, this is inherited from curfile dirname. */
    int out_rooted = 0;

    /* Parse base directory segments if input is relative */
    char base_dir[4096];
    if (!is_abs) {
        rc = util_dirname(base_dir, sizeof(base_dir), curfile, err, errsz);
        if (rc != UTIL_PATH_OK) return rc;

        const char *b = base_dir;

        /* Preserve drive prefix from curfile base if present like "C:/..." */
        if (util_has_drive_prefix(b) && b[2] == '/') {
            drive_prefix[0] = b[0];
            drive_prefix[1] = ':';
            drive_len = 2;
            b += 2;
        }

        out_rooted = (b[0] == '/');

        /* Split base into segments */
        while (*b) {
            while (*b == '/') b++;
            if (!*b) break;

            const char *s = b;
            while (*b && *b != '/') b++;
            size_t len = (size_t)(b - s);
            if (len == 0) continue;

            if (seg_count >= (sizeof(segs)/sizeof(segs[0]))) {
                util_seterr(err, errsz, "too many path segments");
                return UTIL_PATH_ESEGCOUNT;
            }
            segs[seg_count++] = (struct util_seg){ s, len };
        }
    } else {
        /* Absolute input: decide rooted + optional drive prefix from input. */
        const char *p = in_norm;

        if (util_has_drive_prefix(p) && util_is_sep(p[2])) {
            /* allow "C:/..." only */
            drive_prefix[0] = p[0];
            drive_prefix[1] = ':';
            drive_len = 2;
            p += 2; /* leave leading '/' */
        }

        out_rooted = 1;

        /* We’ll parse segments from p below; set in_norm to start at p by shifting pointer. */
        /* For simplicity, just store p back into in_norm via a pointer below. */
    }

    /* Now parse and apply dot/validation from the (normalized) input path */
    const char *p = in_norm;

    /* If we already consumed a drive prefix for absolute input, skip it here too */
    if (is_abs && drive_len == 2 && util_has_drive_prefix(p) && util_is_sep(p[2])) {
        p += 2;
    }

    /* If rooted, skip all leading '/' */
    if (out_rooted) {
        while (*p == '/') p++;
    }

    while (*p) {
        while (*p == '/') p++;
        if (!*p) break;

        const char *s = p;
        while (*p && *p != '/') p++;
        size_t len = (size_t)(p - s);
        if (len == 0) continue;

        /* Dot-only segment classification */
        size_t dots = 0;
        while (dots < len && s[dots] == '.') dots++;
        int all_dots = (dots == len);

        if (all_dots) {
            if (len == 1) {
                /* "." => drop */
                continue;
            } else if (len == 2) {
                /* ".." => pop */
                if (seg_count > 0) {
                    seg_count--;
                    continue;
                }
                util_seterr(err, errsz,
                           is_abs ? "\"..\" escapes root in absolute path"
                                  : "\"..\" escapes base directory in relative path");
                return UTIL_PATH_ETRAVERSAL;
            } else {
                util_seterr(err, errsz, "segment of three or more dots is not allowed");
                return UTIL_PATH_EDOT;
            }
        }

        /* Strict segment validation */
        for (size_t i = 0; i < len; i++) {
            unsigned char c = (unsigned char)s[i];

            if (c == ':') {
                util_seterr(err, errsz, "':' is not allowed in path segments");
                return UTIL_PATH_ECHAR;
            }
            if (!util_is_allowed_seg_char(c)) {
                util_seterr(err, errsz, "illegal character in path (conservative mode)");
                return UTIL_PATH_ECHAR;
            }
        }

        if (seg_count >= (sizeof(segs)/sizeof(segs[0]))) {
            util_seterr(err, errsz, "too many path segments");
            return UTIL_PATH_ESEGCOUNT;
        }
        segs[seg_count++] = (struct util_seg){ s, len };
    }

    /* Build output */
    size_t o = 0;

    if (drive_len == 2) {
        if (o + 2 >= outsz) { util_seterr(err, errsz, "output too long"); return UTIL_PATH_ETOOLONG; }
        out[o++] = drive_prefix[0];
        out[o++] = ':';
    }

    if (out_rooted) {
        if (o + 1 >= outsz) { util_seterr(err, errsz, "output too long"); return UTIL_PATH_ETOOLONG; }
        out[o++] = '/';
    }

    for (size_t i = 0; i < seg_count; i++) {
        if (o > 0 && out[o - 1] != '/') {
            if (o + 1 >= outsz) { util_seterr(err, errsz, "output too long"); return UTIL_PATH_ETOOLONG; }
            out[o++] = '/';
        }

        if (o + segs[i].len >= outsz) {
            util_seterr(err, errsz, "output too long");
            return UTIL_PATH_ETOOLONG;
        }
        memcpy(out + o, segs[i].p, segs[i].len);
        o += segs[i].len;
    }

    if (o >= outsz) { util_seterr(err, errsz, "output too long"); return UTIL_PATH_ETOOLONG; }
    out[o] = '\0';

    if (out[0] == '\0') {
        util_seterr(err, errsz, "resolved path is empty");
        return UTIL_PATH_EINVAL;
    }

    return UTIL_PATH_OK;
}

const char *
util_path_rc_str(enum util_path_rc rc)
{
    switch (rc) {
    case UTIL_PATH_OK:         return "UTIL_PATH_OK";
    case UTIL_PATH_EINVAL:     return "UTIL_PATH_EINVAL";
    case UTIL_PATH_ETOOLONG:   return "UTIL_PATH_ETOOLONG";
    case UTIL_PATH_ECHAR:      return "UTIL_PATH_ECHAR";
    case UTIL_PATH_EDOT:       return "UTIL_PATH_EDOT";
    case UTIL_PATH_ETRAVERSAL: return "UTIL_PATH_ETRAVERSAL";
    case UTIL_PATH_EUNC:       return "UTIL_PATH_EUNC";
    case UTIL_PATH_ESEGCOUNT:  return "UTIL_PATH_ESEGCOUNT";
    default:                   return "UTIL_PATH_(unknown)";
    }
}

