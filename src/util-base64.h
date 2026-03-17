/*
    This is a straight-forward BASE64 decoder, without any special
    tricks like SIMD acceleration.
 */
#ifndef UTIL_BASE64_H
#define UTIL_BASE64_H
#include <stddef.h>
#include <stdint.h>

/**
 * A BASE64 decoder
 *  @param src
 *      This is the source text string. It should consist of only legal BASE64 [A-Za-z0-0/+=]
 *      chara ters.
 *  @param srclen
 *      This is the length of the source string.
 *  @param out
 *      This is where the binary decoded output will be written.
 *  @param outlen
 *      An [in/out] parameter that specifies the length. On input,
 *      it specifies the maximum amount of bytes that can be
 *      written. On ouput, it specifies the number of bytes successfully
 *      written.
 */
int base64_decode(
  const char *src,
  size_t srclen,
  uint8_t *out,
  size_t *outlen);

#endif
