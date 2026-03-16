#ifndef UTIL_BASE64_H
#define UTIL_BASE64_H
#include <stddef.h>
#include <stdint.h>

/**
 * A BASE64 decoder
 * @param src
 *      This is the source text string.
 *  @param srclen
 *          This is the length of the string.
 */
int base64_decode(
  const char *src,
  size_t srclen,
  uint8_t *out,
  size_t *outlen);

#endif
