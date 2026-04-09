#ifndef ZONE_FAST_CLASSIFY_H
#define ZONE_FAST_CLASSIFY_H

#include <stddef.h>
#include <stdint.h>

#include "util-ctz.h"
#include "util-simd.h"

#ifdef _MSC_VER
#  define always_inline __forceinline
#elif defined(__GNUC__) || defined(__clang__)
#  define always_inline __attribute__((always_inline)) inline
#else
#  define always_inline inline
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * An array of these is the `simdjson` style classification "tape" that
 * marks token boundaries.
 */
typedef uint64_t tokentape_t;

typedef void (*zone_fast_classify_fn)(
    const char *data,
    size_t max,
    tokentape_t *tape_whitespace,
    tokentape_t *tape_intoken
);

/**
 * This is the "classification" function run on a block of input data before
 * parsing begins, marking spaces and tokens.
 */
extern zone_fast_classify_fn zone_fast_classify;

/**
 * Call this on program startup in order to initialize the SIMD backend
 * kernel that we are going to use, which are defined in `util-simd.h`.
 */
void zone_fast_classify_init(int backend);

int zone_fast_classify_quicktest(void);


/*
 * ARM has only a CLZ but not CTZ instruction. The
 * solution is to either reverse the bits (RBIT instruction)
 * before calling CTZ, or reverse the bits during
 * classification.
 *
 * We choose reversing bits during classification so
 * therefore, when counting zeroes, we need to come
 * at it from the other direction, doing `clz` instead
 * of `rbit clz`
 */
#if defined(__arm__) || defined(__aarch64__)
# define maybe_reverse(x) __builtin_bitreverse64(x)
# define count_zeroes(x) clz64(x)
#else
# define maybe_reverse(x) (x)
# define count_zeroes(x) ctz64(x)
#endif



/*
 * Tape format:
 *   - one bit per input byte
 *   - each uint64_t covers 64 bytes
 *
 * tape_whitespace:
 *   bit = 0  => byte is ' ' or '\t'
 *   bit = 1  => byte is not ' ' and not '\t'
 *
 * tape_intoken:
 *   bit = 0  => byte is ' ' or '\t' or '\r' or '\n'
 *   bit = 1  => byte is none of those
 *
 * Returns the run length starting at "cursor" by using ctz64() on the
 * shifted tape word, and if that exactly consumes the remaining bits in
 * the current 64-bit word, adds the next word's ctz64() as well.
 */
static always_inline unsigned
classified_length(const tokentape_t *tape, size_t cursor)
{
    /* selects which 64-bit word we are dealing with */
    size_t index = cursor >> 6;
    
    /* selects which bit within the word we start at */
    unsigned shift = (unsigned)(cursor & 63);
    
    /* maximum allowed value of the first length, the bits remaining
     * after the shift */
    unsigned remain = 64u - shift;
    
    /* calculate zeroes for this word, starting at the word-index and bit-index */
#ifdef __arm__
    unsigned len0 = count_zeroes(tape[index] << shift);
#else
    unsigned len0 = count_zeroes(tape[index] >> shift);
#endif
    
    /* calculate zeroes for the start of the next word */
    unsigned len1 = count_zeroes(tape[index + 1]);
    
    /* if we consume all the remaining bits, then return this word's
     * count plus the start of the next word's count, otherwise,
     * return just this count. */
    unsigned mask = (unsigned)(-(int)(len0 >= remain));
    return (len0 & ~mask) | ((remain + len1) & mask);
    
    
    //return (len0 >= remain) ? (remain + len1) : len0;

    //unsigned c = 1 ^ ((len0 - remain) >> (sizeof(unsigned) * 8 - 1));
    //return len0 + ((remain + len1 - len0) & -c);
    
    
    //unsigned crossed = (len0 >= remain);
    //return (unsigned)(len0 - crossed * (len0 - remain) + crossed * len1);
}

#ifdef __cplusplus
}
#endif

#endif
