#include "zone.h"
#include "zone-parse.h"
#include "zone-scan.h"

void zone_parse_init(int backend) {
    zone_atom_name_init(backend);
    zone_atom_name4_init(backend);
    zone_atom_name5_init(backend);
    zone_atom_mask_init(backend);
    zone_parse_header2_init(backend);
}

extern void zone_atom_ht_init(void);
extern void zone_atom_init(int backend);

static const char *backend_name(int backend) {
    switch (backend) {
    case SIMD_AUTO:
        return backend_name(simd_get_best());
        break;
    case SIMD_SCALAR: return "SCALAR";
    case SIMD_SWAR: return "SWAR";
#if defined(SIMD_SSE2)
    case SIMD_SSE2: return "SSE2";
#endif
#if defined(SIMD_SSE42)
    case SIMD_SSE42: return "SSE42";
#endif
#if defined(SIMD_AVX2)
    case SIMD_AVX2: return "AVX2";
#endif
#if defined(SIMD_AVX512)
    case SIMD_AVX512: return "AVX512";
#endif
#if defined(SIMD_NEON)
    case SIMD_NEON: return "NEON";
#endif
#if defined(SIMD_SVE2)
    case SIMD_SVE2: return "SVE2";
#endif
#if defined(SIMD_RISCVV)
    case SIMD_RISCVV: return "RVV";
#endif
    default: return "UNKNOWN";
    }
}

void zone_init(int backend) {
    fprintf(stderr, "[+] SIMD = %s\n", backend_name(backend));
    zone_atom_init(backend);
    zone_scan_init(backend);
    zone_parse_init(backend);
    zone_atom_ht_init();
}

