/* util-pathname.h
 *
 * Conservative pathname resolution utilities.
 *
 * Purpose
 * -------
 * Resolve a user-supplied path against the directory of an existing filename,
 * while performing strict security validation and dot-segment normalization.
 *
 * Behavior
 * --------
 * util_path_resolve_from_file_dir():
 *   - If input_path is absolute:
 *       * output = normalized absolute path
 *       * *is_absolute_out = 1
 *   - If input_path is relative:
 *       * output = dirname(curfile) + input_path (joined)
 *       * *is_absolute_out = 0
 *
 * Dot-segment processing (segment == label between separators):
 *   - "."  : removed
 *   - ".." : removes one prior segment; error if it would escape the base/root
 *   - "..." or more dots-only: error
 *
 * Normalization:
 *   - Accepts both '/' and '\\' as separators in inputs; output uses '/'.
 *   - Collapses repeated separators.
 *
 * Conservative validation:
 *   - Rejects control characters and DEL (0x00..0x1F, 0x7F).
 *   - Rejects UNC paths (\\server\share) as too ambiguous / risky.
 *   - Per-segment allowlist: [A-Za-z0-9._-] only.
 *   - Rejects ':' anywhere except a leading Windows drive prefix "C:" that is
 *     immediately followed by a separator (i.e., only "C:\..." or "C:/...").
 *
 * Notes
 * -----
 * - This is intentionally strict. If you need to permit spaces or additional
 *   characters, widen util_path_is_allowed_seg_char() in util-pathname.c.
 * - This does not hit the filesystem; it is purely lexical processing.
 */

#ifndef UTIL_PATHNAME_H
#define UTIL_PATHNAME_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Return codes */
enum util_path_rc {
    UTIL_PATH_OK = 0,
    UTIL_PATH_EINVAL,
    UTIL_PATH_ETOOLONG,
    UTIL_PATH_ECHAR,
    UTIL_PATH_EDOT,        /* "..." or more dots-only segment */
    UTIL_PATH_ETRAVERSAL,  /* ".." escapes base/root */
    UTIL_PATH_EUNC,        /* UNC path rejected */
    UTIL_PATH_ESEGCOUNT    /* too many segments */
};

/* Resolve input_path against dirname(curfile) if relative; otherwise preserve
 * absolute, returning *is_absolute_out=1.
 *
 * out/outsz: output buffer for normalized path (always '/' separators)
 * curfile:   current filename (used only to compute base directory for relatives)
 * input_path: include/relative/absolute path to resolve
 * is_absolute_out: set to 1 if input_path was absolute, else 0
 * err/errsz: optional human-readable error buffer (may be NULL/0)
 */
enum util_path_rc
util_path_resolve_from_file_dir(char *out, size_t outsz,
                                const char *curfile,
                                const char *input_path,
                                int *is_absolute_out,
                                char *err, size_t errsz);

/* Convert util_path_rc to a stable string (never returns NULL). */
const char *
util_path_rc_str(enum util_path_rc rc);

#ifdef __cplusplus
}
#endif

#endif /* UTIL_PATHNAME_H */

