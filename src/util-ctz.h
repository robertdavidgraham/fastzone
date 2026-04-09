/*
    "count trailing zeroes"
 
 This is a trick at the heart of some branchless coding, where we move many
 tests into a single integer, then count the number of "trailing zeroes".
 
 For example, when skipping tokens and spaces, we test the next 64 BYTES
 if they are a space (using SIMD/SWAR) then mark a 0 bit whenever they are.
 
 Then, to count the number of spaces we need to skip, we execute this
 instruction, which counts them in 1 clock cycle (ARM) or 3 cycles (x86).
 
 Today's massively out-of-order processors cannot reason well for all
 the branches that happen when testing each byte whether it's a space,
 but they can predict far in the future if we do this without branches.
 
 The word "trailing" is arbitrary, from another point of view it's
 "leading" zeroes. It's the "endian" problem all over again, but
 now bits in a word. What we are doing is going in the lowest-order
 bit and going upwards, so 0x0FFFFFF8 returns a value of '3' and
 not '4'. It's up to you to decide if those are trailing or leading.
 
 On x86, the old instruction was `bsf` or "bit-scan-forward". Again,
 it's arbitrary where you call this scanning forward or backwards,
 it's from low-order to high-order.
 
 In modern x86, it's encoded in assembly as "rep bsf". It has an
 extra prefix byte you'd expect from loops but it still encodes to
 a single uop.
 
 The `bsf` count is undefined when the value is all zeroes, when
 you'd expect it to return 32 or 64.
 
 Since Haswell and the BMI1 extension, x86 CPUs have supported an
 alternate `tzcount` instruction that is defined correctly for
 when the input value is zero.
 
 Microsoft's `_BitCountForward()` intrinsic inserts a check for zero,
 while the gcc/clang `__builtin_ctzll()` does not. Therefore,
 we have to check for this ourselves.
 
 
 */
#ifndef UTIL_CTZ_H
#define UTIL_CTZ_H
#include <stdint.h>

/* ------------------------- compiler portability helpers -------------------- */

#if defined(_MSC_VER)
  #include <intrin.h>

  /* This forces the Microsoft compiler to use an inrinsic for _BitScanForward
   * rather than calling a function */
  #pragma intrinsic(_BitScanForward)
  #if defined(_M_X64) || defined(_M_ARM64)
    #pragma intrinsic(_BitScanForward64)
  #endif

static inline unsigned ctz32(unsigned x)
{
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
    if (x == 0) return 32;
#endif
    unsigned long idx;
    _BitScanForward(&idx, (unsigned long)x);
    return (unsigned)idx;
}

static inline unsigned ctz64(uint64_t x)
{
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
    if (x == 0) return 64;
#endif
    unsigned long idx;
  #if defined(_M_X64) || defined(_M_ARM64)
    _BitScanForward64(&idx, (unsigned __int64)x);
  #else
    // 32-bit MSVC: split.
    unsigned lo = (unsigned)(x);
    if (lo) {
        _BitScanForward(&idx, (unsigned long)lo);
        return (unsigned)idx;
    }
    unsigned hi = (unsigned)(x >> 32);
    _BitScanForward(&idx, (unsigned long)hi);
    return (unsigned)idx + 32u;
  #endif
    return (unsigned)idx;
}

#else
static inline unsigned ctz32(unsigned x)  {
    #if defined(__x86_64__) || defined(__i386__)
    if (x == 0) return 32; /* x86 `bsf` undefinedf or x==0 */
    #endif
    return (unsigned)__builtin_ctz(x);
}
static inline unsigned ctz64(uint64_t x)  {
#if defined(__x86_64__) || defined(__i386__)
    if (x == 0) return 32; /* x86 `bsf` undefinedf or x==0 */
#endif
    return (unsigned)__builtin_ctzll(x);
}
static inline unsigned clz64(uint64_t x)  {
#if defined(__x86_64__) || defined(__i386__)
    if (x == 0) return 32; /* x86 `bsf` undefinedf or x==0 */
#endif
    return (unsigned)__builtin_clzll(x);
}

#endif

#endif
