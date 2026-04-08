#include "util-simd.h"
#include <string.h>

int g_zone_backend = SIMD_SCALAR1;

#if SIMD_x86
static inline int dns_cpu_has_sse2(void) {
#if defined(__x86_64__) || defined(_M_X64)
  return 1; /* SSE2 is baseline on x86-64 */
#elif defined(__i386__) || defined(_M_IX86)
  #if defined(__GNUC__) || defined(__clang__)
    return __builtin_cpu_supports("sse2");
  #elif defined(_MSC_VER)
    int info[4] = {0};
    __cpuid(info, 1);
    return (info[3] & (1 << 26)) != 0; /* EDX bit 26 = SSE2 */
  #else
    return 0;
  #endif
#else
  return 0;
#endif
}
#endif

#if defined(SIMD_ARM) && 0
static inline int dns_cpu_has_neon(void) {
#if SIMD_NEON64
  #if defined(__aarch64__)
    #if defined(__APPLE__)
      return 1; /* NEON/ASIMD mandatory on Apple arm64 */
    #elif defined(__linux__)
      unsigned long hw = getauxval(AT_HWCAP);
      return (hw & HWCAP_ASIMD) != 0;
    #else
      return 1;
    #endif
  #else
    return 1;
  #endif
#else
  return 0;
#endif
}
#endif


simd_backend_t simd_get_best(void) {
#if SIMD_AVX2
  if (dns_cpu_has_avx2()) return SIMD_AVX2;
#endif
#if SIMD_SSE2
  if (dns_cpu_has_sse2()) return SIMD_SSE2;
#endif
#if SIMD_NEON64
  if (dns_cpu_has_neon())
      return SIMD_NEON64;
#endif
  return SIMD_SWAR; /* good portable fast-path */
}

int cpu_has_avx2(void) {
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
  #if defined(__GNUC__) || defined(__clang__)
    /* Requires compiling with -mavx2? __builtin_cpu_supports works without, but AVX2 code
       must still be compiled in (we gate by __AVX2__ for codegen). */
    return __builtin_cpu_supports("avx2");
  #elif defined(_MSC_VER)
    int info[4] = {0};
    __cpuid(info, 0);
    int nIds = info[0];
    if (nIds < 7) return 0;
    __cpuidex(info, 7, 0);
    return (info[1] & (1 << 5)) != 0; /* EBX bit 5 = AVX2 */
  #else
    return 0;
  #endif
#else
  return 0;
#endif
}
const char *simd_current_name(void) {
    return simd_name(g_zone_backend);
}

const char *simd_name(int backend) {
    switch (backend) {
    case SIMD_SCALAR1:
        return "SCALAR1";
    case SIMD_SCALAR2:
        return "SCALAR2";
    case SIMD_SWAR:
        return "SWAR";
#ifdef SIMD_SSE2
    case SIMD_SSE2:
        return "SSE2";
#endif
#ifdef SIMD_SSE42
    case SIMD_SSE42:
        return "SSE42";
#endif
#ifdef SIMD_AVX2
    case SIMD_AVX2:
        return "AVX2";
#endif
#ifdef SIMD_AVX512
    case SIMD_AVX512:
        return "AVX512";
#endif
#ifdef SIMD_NEON32
    case SIMD_NEON32:
        return "NEON32";
#endif
#ifdef SIMD_NEON64
    case SIMD_NEON64:
        return "NEON64";
#endif
#ifdef SIMD_SVE2
    case SIMD_SVE2:
        return "SVE2";
#endif
#ifdef SIMD_RISCVV
    case SIMD_RISCVV:
        return "RISCVV";
#endif
    default:
        return "UNKNOWN";
    }
}


int simd_from_name(const char *name) {
    if (strcmp(name, "SCALAR") == 0)
        return SIMD_SCALAR1;
    if (strcmp(name, "SCALAR1") == 0)
        return SIMD_SCALAR1;
    if (strcmp(name, "SCALAR2") == 0)
        return SIMD_SCALAR1;
    if (strcmp(name, "SWAR") == 0)
        return SIMD_SWAR;
#ifdef SIMD_SSE2
    if (strcmp(name, "SSE2") == 0)
        return SIMD_SSE2;
#endif
#ifdef SIMD_SSE42
    if (strcmp(name, "SSE42") == 0)
        return SIMD_SSE42;
    if (strcmp(name, "SSE4.2") == 0)
        return SIMD_SSE42;
#endif
#ifdef SIMD_AVX2
    if (strcmp(name, "AVX2") == 0)
        return SIMD_AVX2;
    if (strcmp(name, "AVX256") == 0)
        return SIMD_AVX2;
#endif
#ifdef SIMD_AVX512
    if (strcmp(name, "SSE512") == 0)
        return SIMD_SSE512;
#endif
#ifdef SIMD_NEON32
    if (strcmp(name, "NEON") == 0)
        return SIMD_NEON32;
    if (strcmp(name, "NEON32") == 0)
        return SIMD_NEON32;
#endif
#ifdef SIMD_NEON64
    if (strcmp(name, "NEON") == 0)
        return SIMD_NEON64;
    if (strcmp(name, "NEON64") == 0)
        return SIMD_NEON64;
#endif
#ifdef SIMD_SVE2
    if (strcmp(name, "SVE2") == 0)
        return SIMD_SVE2;
#endif
#ifdef SIMD_RISCVV
    if (strcmp(name, "RISCVV") == 0)
        return SIMD_RISCVV;
    if (strcmp(name, "RVV") == 0)
        return SIMD_RISCVV;
#endif
    return 0;
}
