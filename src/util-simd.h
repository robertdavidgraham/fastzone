/*
    SIMD utilities
 
 In my code, I want to select from a number of SIMD backends -- not simply
 choose the best at runtime, but to select different ones to benchmark against.
 
 * On ARM, I want to test NEON and SVE2 against non-SIMD.
 * On x86, I want to test SSE2, AVX2, and AVX512.
 * I want to include RISCVV, even though that SIMD isn't widely
   supported or has a stable interface.
 * In the future, I want to support IBM Power, as IBM continues to support
   it as a Tier-1 Linux systme.
 * In the future, I want to support Loongson, as China is trying to push
   it into a Tier-1 Linux system.
 
 ARM NEON is slightly different on 32-bit and 64-bit architectures. Hence,
 I do NEON32 and NEON64 as different choices.
 
 This code uses the trick of #defining enums as themselves, so you
 can test for it either way, with the preprocessor or with code.
 
 You can loop from [1..SIMD_MAX] to enumerate all the ones supported
 on the platform. The value 0 is SIMD_AUTO, which automatially chooses
 the best one.
 
 Both Windows and Linux/Apple are supported.
 
 
 */
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
#define SIMD_SCALAR1    SIMD_SCALAR1
#define SIMD_SCALAR2    SIMD_SCALAR2
#define SIMD_SWAR       SIMD_SWAR


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
  #define SIMD_NEON64 SIMD_NEON64
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
  SIMD_SCALAR1,
  SIMD_SCALAR2,
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
#ifdef SIMD_NEON32
  SIMD_NEON32,
#endif
#ifdef SIMD_NEON64
  SIMD_NEON64,
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

const char *simd_current_name(void);
const char *simd_name(int backend);
int simd_from_name(const char *name);

#endif
