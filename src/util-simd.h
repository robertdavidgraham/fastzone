#ifndef SIMD_H
#define SIMD_H
#include "util-ctz.h"

#define g_backend_selected g_zone_backend
extern int g_zone_backend;

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
  #define SIMD_X86 1
#endif

#if defined(__aarch64__) || defined(__arm__) || defined(_M_ARM64) || defined(_M_ARM)
  #define SIMD_ARM 1
#endif

#if defined(__riscv) || defined(_M_RISCV)
  #define SIMD_RISCV 1
#endif

/* zone-simd-detect.h
 *
 * Define SIMD_* only when the current translation unit
 * may legally emit those instructions.
 *
 * Works on macOS, Linux, Windows
 * (clang, clang-cl, gcc, MSVC)
 */

/* =========================
 * Always available
 * ========================= */
#undef SIMD_SCALAR
#define SIMD_SCALAR SIMD_SCALAR
#define SIMD_SWAR   SIMD_SWAR


/* =========================
 * x86 / x86_64
 * ========================= */

#if defined(__x86_64__) || defined(_M_X64) || defined(__amd64__) || defined(_M_AMD64)
  /* x86-64 guarantees SSE2 */
  #define SIMD_SSE2 SIMD_SSE2
#elif defined(__i386__) || defined(_M_IX86)
  #if defined(__SSE2__) || (defined(_MSC_VER) && defined(_M_IX86_FP) && (_M_IX86_FP >= 2))
    #define SIMD_SSE2 SIMD_SSE2
  #endif
#endif

/* SSE 4.2 */
#if defined(__SSE4_2__) || (defined(_MSC_VER) && defined(__AVX__)) || (defined(_MSC_VER) && defined(__SSE4_2__))
  #define SIMD_SSE42 SIMD_SSE42
#endif

/* AVX2 */
#if defined(__AVX2__) || (defined(_MSC_VER) && defined(__AVX2__))
#define SIMD_AVX2 SIMD_AVX2
#endif

/* AVX-512 (foundation) */
#if defined(__AVX512F__) || (defined(_MSC_VER) && defined(__AVX512F__))
#define SIMD_AVX512 SIMD_AVX512
#endif


/* =========================
 * ARM / AArch64
 * ========================= */

/* NEON is baseline on AArch64 */
#if defined(__aarch64__) || defined(_M_ARM64) || defined(_M_ARM64EC)
  #define SIMD_NEON SIMD_NEON
#endif

/* SVE2 (must be enabled in -march) */
#if defined(__aarch64__) && defined(__ARM_FEATURE_SVE2)
  #define SIMD_SVE2 SIMD_SVE2
#endif


/* =========================
 * RISC-V Vector (V)
 * ========================= */

#if defined(__riscv) && defined(__riscv_vector)
  #define SIMD_RISCVV SIMD_RISCVV
#endif




#if SIMD_X86
  #include <immintrin.h>
#endif

#if SIMD_ARM && defined(__ARM_NEON)
  #include <arm_neon.h>
#endif

typedef enum zone_backend {
  SIMD_AUTO = 0,
  SIMD_SCALAR,
  SIMD_SWAR,
#ifdef SIMD_SSE2
  SIMD_SSE2,
#endif
#ifdef SIMD_SSE42
  SIMD_SSE42,
#endif
#ifdef SIMD_AVX2
  SIMD_AVX2,
#endif
#ifdef SIMD_AVX512
  SIMD_AVX512,
#endif
#ifdef SIMD_NEON
  SIMD_NEON,
#endif
#ifdef SIMD_SVE2
  SIMD_SVE2,
#endif
#ifdef SIMD_RISCVV
  SIMD_RISCVV,
#endif
    SIMD_MAX
} simd_backend_t;



simd_backend_t simd_get_best(void);

const char *simd_get_name(void);

#endif
