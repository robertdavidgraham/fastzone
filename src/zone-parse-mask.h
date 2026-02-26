/* zone-atom-mask.h
 *
 * Whitespace mask classifier used by the DNS zonefile parser’s fast token scanner.
 *
 * OVERVIEW
 *   This module provides a low-level “classification mask” primitive in the style of simdjson:
 *     - Classify a fixed-width chunk of upcoming bytes into a bitmask.
 *     - Use bit operations (ctz/bit scans) in higher-level code to find token boundaries.
 *     - Consume bytes by shifting the mask down and refilling when exhausted.
 *
 * CLASSIFICATION RULE (THIS MODULE ONLY)
 *   - ASCII space ' ' and horizontal tab '\t' are classified as whitespace => bit 0.
 *   - All other bytes are classified as non-whitespace => bit 1.
 *
 *   IMPORTANT: This module does NOT understand comments (;), quotes, escapes, or
 *   parentheses for multiline zonefile records. Those behaviors must be handled in
 *   higher-level parsing stages. This module is intentionally minimal and fast.
 *
 * SIMD BACKENDS / RUNTIME DISPATCH
 *   - SIMD identifiers and enum values are declared in util-simd.h:
 *       SIMD_AUTO, SIMD_SCALAR, SIMD_SWAR, SIMD_SSE2, SIMD_SSE42, SIMD_AVX2,
 *       SIMD_AVX512, SIMD_NEON, SIMD_SVE2, SIMD_RISCVV, SIMD_MAX
 *   - A backend is only present if the corresponding SIMD_* macro is defined.
 *     If the compiler/target does not support a backend, util-simd.h will not
 *     define the macro and the enum will not contain that value.
 *   - util-simd.h also declares simd_get_best(), used to resolve SIMD_AUTO.
 *
 * API SHAPE
 *   - The caller owns an absolute cursor (size_t) into a buffer `data`.
 *   - zone_atom_mask(data, cursor, &mask, &avail):
 *       - Reads from data+cursor.
 *       - Produces a mask in `mask` and the number of valid bits in `avail`.
 *       - The backend’s width determines avail (commonly 16/32/64).
 *       - Bit i (LSB = byte 0 of the chunk) corresponds to data[cursor+i].
 *   - zone_atom_consume(data, cursor, &mask, &avail, length):
 *       - Shifts mask down by `length`, reduces avail, refills when needed.
 *       - Returns the new cursor (cursor + length), consuming across chunk boundaries.
 *
 * SAFETY / PORTABILITY CONTRACT
 *   - Backends may perform unaligned loads. The caller must ensure at least
 *     `avail` bytes are readable at data+cursor whenever zone_atom_mask() is called
 *     (common approach: parse within a padded buffer).
 *   - All non-portable SIMD code is behind #ifdef SIMD_* blocks.
 *   - The file must compile on Windows, macOS, and Linux; unsupported SIMD
 *     headers/intrinsics are only referenced when the matching SIMD_* macro is defined.
 *
 * SELF TEST
 *   - zone_atom_mask_quicktest() runs a small set of deterministic tests.
 *   - It iterates SIMD implementations from SIMD_AUTO+1 to SIMD_MAX-1, initializes
 *     each, and validates 20 test inputs (each exactly 64 bytes) against expected
 *     64-bit masks.
 *   - It accumulates failures in an `err` variable and returns err (0 = success).
 *   - On failure, it prints: "atom.mask:%d failed test\n" with the test number.
 */

#ifndef ZONE_ATOM_MASK_H
#define ZONE_ATOM_MASK_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif


void zone_atom_mask_init(int backend);

static inline int is_zone_space(int c) {
    if (c == ' ')
        return 1;
    else
    return  
            (c == '\t') ||
            (c == ')') ||
            (c == '(') ||
            (c == '\r') ||
            (c == '\n') ||
    (c == ';');
}

int zone_atom_mask_quicktest(void);

/* =============================================================================
 * Zonefile mask-driven scanning helpers (simdjson-style)
 *
 * Purpose:
 *   These helpers implement a simdjson-style scanning pattern for parsing DNS
 *   zonefile records:
 *     - A SIMD classifier produces a bitmask over the next chunk of bytes.
 *     - Higher-level parsing uses bit operations (ctz) over the mask to quickly
 *       find boundaries (whitespace, triggers, etc.).
 *     - Cursor advancement is done while keeping the mask and its availability
 *       consistent; when the chunk is exhausted the mask is refilled.
 *
 * Assumptions / invariants:
 *   - The input buffer is prepared so it is always safe to read at least 64 bytes
 *     beyond (data + cursor).
 *   - A '\n' newline sentinel exists at or after the logical end of the buffer.
 *   - The mask classifier (`zone_atom_mask`) provides a mask where:
 *       bit=0 for whitespace (' ' or '\t')
 *       bit=1 for non-whitespace (everything else)
 *     and sets `*avail` to the number of valid bits in the mask (16/32/64).
 *
 * External helpers:
 *   - size_t zone_scan_eol(const char *data, size_t cursor, size_t max);
 *     Scans forward to (and including) the end-of-line newline and returns the
 *     new cursor positioned at that '\n' (or just after it, depending on your
 *     definition; this code assumes it returns the cursor at the '\n' position).
 *
 * Functions:
 *   - zone_mask_start():
 *       Initializes the mask+avail at the given cursor.
 *   - zone_mask_skip_nospace():
 *       Skips forward a fixed number of bytes (cursor += length), shifting/refilling
 *       the mask as needed. If it lands exactly at the end of availability, it must
 *       still advance cursor fully first, then refill the mask.
 *   - zone_mask_skip_space():
 *       Skips whitespace and also handles “deemed whitespace” triggers while
 *       scanning:
 *         ';' comment: skip to end-of-line using zone_scan_eol(). If depth>0, also
 *                      skip the '\n' and continue scanning.
 *         '('         : depth++ , consume it, continue scanning
 *         ')'         : depth-- , consume it, continue scanning
 *         '\n'        : if depth>0 consume and continue; else stop (end of record line)
 *
 *   The caller passes `depth` which is the current parentheses depth for multiline
 *   records. Parentheses may appear while scanning whitespace between tokens.
 * =============================================================================
 */

void zone_mask_start(const char *data, size_t cursor,  size_t max,
                     uint64_t *mask, unsigned *avail);

/* Skip a fixed number of bytes, regardless of their contents.
 * Returns cursor+length.
 *
 * Important requirement:
 *   If skipping lands exactly at the end of availability, still advance cursor
 *   to the new position first, then refill the mask (so the mask corresponds to
 *   the returned cursor).
 */
size_t zone_mask_skip_nospace2(const char *data, size_t cursor,  size_t max,
                              uint64_t *mask, unsigned *avail, size_t length);

static inline size_t
zone_mask_skip_nospace1(const char *data, size_t cursor, size_t max,
                        size_t length) {
    if (cursor < max)
        return cursor + length;
    else
        return max + 1;
}

/* Skip whitespace and handle special triggers that are treated like whitespace.
 * Returns the cursor positioned at the first non-space (token start) OR at '\n'
 * when depth==0 (end-of-record line).
 *
 * depth rules:
 *   - '(' increments *depth
 *   - ')' decrements *depth
 *   - If '\n' and *depth>0: consume '\n' and continue (multiline)
 *   - If '\n' and *depth==0: stop and return (end of record)
 *
 * comment rule:
 *   - On ';', skip to end-of-line using zone_scan_eol(data, cur, max).
 *   - If *depth>0 after that, consume the '\n' and continue scanning.
 *   - Otherwise stop on that '\n' (end of record).
 *
 * The function assumes:
 *   - readable padding of at least 64 bytes past cur
 *   - a '\n' sentinel exists at/after end
 */

size_t
zone_mask_skip_space3(const char *data, size_t cursor, size_t max, unsigned *depth);

void zone_atom_mask_init(int backend);

#ifdef __cplusplus
}
#endif

#endif /* ZONE_ATOM_MASK_H */

