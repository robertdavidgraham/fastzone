/*
    Branchless "integer" parser.
 
 This is fast parser for integers in string format like "1234"
 that will become the value 1234 when parsed.
 
 It uses SWAR/SIMD techniques. The caller must pad the buffer
 to make sure there's at least 8 characters off the end of the
 buffer that we can load.
 
 It's a happy-path parser. It makes assumptions like the length
 being 8 characters or fewer (max 0x5F5E100 result). Errors
 are accumulated rather than changing parsing behavior.
 
 The caller will have to check the error and switch to a slow-path
 parser when they occur. The slow-path parser will presumably
 deal with either parsing longer strings, or report errors
 like which charater is not a digit.
 */
#ifndef UTIL_PARSEINT_H
#define UTIL_PARSEINT_H
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#if (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
# define bswap_maybe(x) (x)
#else
# define bswap_maybe(x) __builtin_bswap64((uint64_t)(x))
#endif

/**
 * Branchless and happy-path integer parser. Parses up to eight digits,
 * "99999999" or 0x5F5E100. Validates all characters are digits. Caller
 * must know length. (We assume caller is using SIMD to classify input strings
 * to discover length, otherwise it's pointless using this function.)
 * This is defined as an inline function because it's assumed the caller
 * wants to avoid the branch of a function-call and would want code-bloat
 * instead.
 *
 * @param data
 *  A string containing an integer, like "1234". The buffer must be readable
 *  for at least 8 bytes.
 * @param length
 *  The number of digits to parse from the buffer. The buffer may be longer
 *  than this length containing other stuff, we stop at the specified length.
 *  At least one digit and no more than eight must be given, or it triggers
 *  an error.
 * @param err
 *  Will be set to '1' on an error, and will not be touched otherwise. It's intent
 *  is to "accumulate" errors in branchless code.
 */
static inline uint64_t
parse_integer(const char *data, size_t length, int *err) {
    /* Accumlate errors in case of a bad length. This won't stop
     * parsing, but will indicate the result is malformed. */
    *err |= (length == 0);
    *err |= (length > 8);

    /* Grab the next 8 bytes. The caller guarantees that there are at
     * last 8 extra bytes we can read past the end of their buffers. */
    uint64_t x;
    memcpy(&x, data, 8);
    
    /* Mask off the unused bytes. Most integers will be shorter than
     * the full 8 bytes, this gets rid of the trailing data. */
    uint64_t mask = (~0ULL) >> ((8ULL - length) << 3);
    x &= mask;

    /* Verify these are all digits in the range ['0'..'9'] */
    uint64_t lo  = x - (0x3030303030303030ULL & mask);
    uint64_t hi  = (0x3939393939393939ULL & mask) - x;
    uint64_t is_bad = (lo | hi) & 0x8080808080808080ULL;
    *err |= (is_bad != 0);


    /* Swap the bytes around on little-endian architectures, which
     * is most all of the time. Modern CPUs byte-swap with a single
     * instruction. */
    uint64_t shift = (8ULL - length) << 3;
    lo = bswap_maybe(lo) >> shift;

    /* This is the expensive part, with each multiply requiring 3 clock cycles. */
    uint64_t pair = ((lo * 10ULL) + (lo >> 8)) & 0x00ff00ff00ff00ffULL;
    uint64_t quad = ((pair * 100ULL) + (pair >> 16)) & 0x0000ffff0000ffffULL;
    return ((quad * 10000ULL) + (quad >> 32)) & 0xffffffffULL;
}

static inline int parse_integer_selftest(void) {
    char *testcase = "1234567";
    int err = 0;
    err |= (parse_integer(testcase, 1, &err) == 1);
    err |= (parse_integer(testcase, 2, &err) == 12);
    err |= (parse_integer(testcase, 3, &err) == 123);
    err |= (parse_integer(testcase, 4, &err) == 1234);
    err |= (parse_integer(testcase, 5, &err) == 12345);
    err |= (parse_integer(testcase, 6, &err) == 123456);
    err |= (parse_integer(testcase, 7, &err) == 1234567);
    return err;
}

#endif
