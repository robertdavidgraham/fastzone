#ifndef UTIL_HEX16_H
#define UTIL_HEX16_H
#include <stdint.h>
#include <stddef.h>

/**
 * Decode hex strings (BASE16).
 * @param src
 *      The source text string.
 * @param srclen
 *      The length of the source string, consisting of an even number of all hex digits.
 * @param dst
 *      Where the binary data will be written.
 * @param dstlen
 *      On IN, the maximum size of the buffer. On OUT, the number of bytes written, which should
 *      be half the srclen.
 * @return 0 on failure, 1 on success.
 */
int base16_decode(const char *src, size_t srclen, uint8_t *dst, size_t *dstlen);

#endif
