#ifndef UTIL_CTZ_H
#define UTIL_CTZ_H
#include <stdint.h>

/* ------------------------- compiler portability helpers -------------------- */

#if defined(_MSC_VER)
  #include <intrin.h>
  #pragma intrinsic(_BitScanForward)
  #if defined(_M_X64) || defined(_M_ARM64)
    #pragma intrinsic(_BitScanForward64)
  #endif

static inline unsigned ctz32(unsigned x)
{
    unsigned long idx;
    _BitScanForward(&idx, (unsigned long)x);
    return (unsigned)idx;
}

static inline unsigned ctz64(uint64_t x)
{
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
static inline unsigned ctz32(unsigned x)  { return (unsigned)__builtin_ctz(x); }
static inline unsigned ctz64(uint64_t x)  { return (unsigned)__builtin_ctzll(x); }
#endif

#endif
