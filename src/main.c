#include "zone-scan.h"
#include "zone-parse.h"
#include "zone-atom-name.h"
#include "zone-atom.h"
#include "zone-token.h"
#include "zone-workq.h"
#include "zone-qbench.h"
#include "zone-fbench.h"
#include "zone.h"
#include "zone-fast-classify.h"
#include "zone-fast-header.h"
#include "zone-parse-record.h"
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ctype.h>

#ifdef _WIN32
#define _CRT_NONSTDC_NO_DEPRECATE
#include <io.h>
#define close _close
#define open _open
#else
#include <sys/time.h>
#include <unistd.h>
#endif

#ifdef _WIN32
// Source - https://stackoverflow.com/a/26085827
// Posted by Michaelangel007, modified by community. See post 'Timeline' for change history
// Retrieved 2026-03-17, License - CC BY-SA 3.0
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <stdint.h> // portable: uint64_t   MSVC: __int64 

// MSVC defines this in winsock2.h!?
typedef struct timeval {
    long tv_sec;
    long tv_usec;
} timeval;

static int gettimeofday(struct timeval* tp, struct timezone* tzp)
{
    // Note: some broken versions only have 8 trailing zero's, the correct epoch has 9 trailing zero's
    // This magic number is the number of 100 nanosecond intervals since January 1, 1601 (UTC)
    // until 00:00:00 January 1, 1970 
    static const uint64_t EPOCH = ((uint64_t)116444736000000000ULL);

    SYSTEMTIME  system_time;
    FILETIME    file_time;
    uint64_t    time;

    GetSystemTime(&system_time);
    SystemTimeToFileTime(&system_time, &file_time);
    time = ((uint64_t)file_time.dwLowDateTime);
    time += ((uint64_t)file_time.dwHighDateTime) << 32;

    tp->tv_sec = (long)((time - EPOCH) / 10000000L);
    tp->tv_usec = (long)(system_time.wMilliseconds * 1000);
    return 0;
}
#endif



int my_benchmark(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <zonefile>\n", argv[0]);
        return 1;
    }
    
    const char *filename = argv[1];
    
    int fd = open(filename, O_RDONLY);
    if (fd == -1) {
        perror(filename);
        return 1;
    }
    
    uint64_t total_records = 0;
    uint64_t total_bytes = 0;
    
    struct timeval start, end;
    gettimeofday(&start, NULL);
    
    zone_workq_t wq;
    zone_workq_init(&wq);
    zone_readfile(&wq, fd, &total_records, &total_bytes, 0, filename, 0, 0, 0);
    gettimeofday(&end, NULL);
    
    double elapsed = (end.tv_sec - start.tv_sec) +
                    (end.tv_usec - start.tv_usec) / 1000000.0;
    double gbps = (total_bytes / (1024.0 * 1024.0 * 1024.0)) / elapsed;
    
    printf("\nParsed %ld records in %.4f seconds\n", (long)total_records, elapsed);
    printf("Throughput: %.2f GB/s\n", gbps);
    printf("Records/sec: %.0f\n", total_records / elapsed);
    printf("Backend: %s\n", simd_current_name());
    close(fd);
    return 0;
}





extern void zone_atom_ttl_bench(void);

/**
 * Scan the command-line parameters looking for one of the well-known names
 * for a SIMD backend. If found, remove that from the list, and return it.
 */
static int get_simd_backend(int argc, char **argv) {
    for (int i=1; i<argc; i++) {
        int backend = simd_from_name(argv[i]);
        if (backend) {
            /* remove it */
            memmove(&argv[i], &argv[i+1], &argv[argc] - &argv[i]);
            return backend;
        }
    }
    return 0;
}

int main(int argc, char *argv[]) {
    fprintf(stderr, "--- fastzone/0.1 ---\n");
    
    int backend = get_simd_backend(argc, argv);
    if (backend) {
        fprintf(stderr, "[+] SIMD selected: %s\n", simd_name(backend));
    }
    
    
    /*
     * WARNING: don't start reading the code here, read the
     * README.md file first.
     */

    /*
     * Must be called beore anything. Things won't work if not
     * initialized.
     */
    zone_init(backend);

    int err = 0;
    err += zone_fast_classify_quicktest();
    err += zone_fast_header_quicktest(SIMD_NEON64);
    err += zone_parse_header2_quicktest();
    err += zone_atom_quicktest();
    err += zone_parse_header_quicktest();
    err += zone_parse_quicktest();
    if (err)
        fprintf(stderr, "[-] selftest failed\n");

    /*
     * This is for doing simple built-in benchmarks of the various
     * components, rather than doing a full benchmark on a file.
     */
    if (argc > 1 && (strcmp(argv[1], "qbench") == 0 || strcmp(argv[1], "--qbench") == 0)) {
        zone_quick_benchmarks();
        return 0;
    }

    if (argc > 1) {
        zone_file_bench(argv[1], backend);
    } else {
        zone_file_bench("ns.se.zone", backend);
    }
                   
    return 0;
    
    //err += zone_atom_mask_quicktest();
    
    /* zone_init(SIMD_NEON64);
    err += zone_atom_name5_quicktest();
    err += zone_atom_name4_quicktest();
*/
    /*
     * Make sure that everything is in basic working order.
     */
    //err += zone_parse_header_quicktest();
    err += zone_scan_quicktest();
    err += zone_atom_name4_quicktest();
    err += zone_atom_name5_quicktest();
    if (err) {
        fprintf(stderr, "[-] self test failed\n");
        return 1;
    }
  
#if 0
    quick_parse_name1_benchmark(SIMD_SCALAR1);
    quick_parse_name1_benchmark(SIMD_SWAR);
#ifdef SIMD_NEON64
    quick_parse_name1_benchmark(SIMD_NEON64);
#endif
#ifdef SIMD_SVE2
    quick_parse_name1_benchmark(SIMD_SVE2);
#endif

    quick_parse_name2_benchmark(SIMD_SCALAR1);
    quick_parse_name2_benchmark(SIMD_SWAR);
#ifdef SIMD_NEON64
    quick_parse_name2_benchmark(SIMD_NEON64);
#endif
#ifdef SIMD_SVE2
    quick_parse_name2_benchmark(SIMD_SVE2);
#endif

    quick_parse_name3_benchmark(SIMD_SCALAR1);
    quick_parse_name3_benchmark(SIMD_SWAR);
#ifdef SIMD_NEON64
    quick_parse_name3_benchmark(SIMD_NEON64);
#endif
#ifdef SIMD_SVE2
    quick_parse_name3_benchmark(SIMD_SVE2);
#endif
#endif
    
    quick_parse_name4_benchmark(SIMD_SCALAR1);
    //quick_parse_name4_benchmark(SIMD_SWAR);
#ifdef SIMD_NEON64
    quick_parse_name4_benchmark(SIMD_NEON64);
#endif
#ifdef SIMD_SVE2
    quick_parse_name4_benchmark(SIMD_SVE2);
#endif

    quick_parse_name5_benchmark(SIMD_SCALAR1);
    quick_parse_name5_benchmark(SIMD_SWAR);
#ifdef SIMD_NEON64
    quick_parse_name5_benchmark(SIMD_NEON64);
#endif
#ifdef SIMD_SVE2
    quick_parse_name5_benchmark(SIMD_SVE2);
#endif


    /*
     * Do the simplest benchmarks
     */
    quick_scan_benchmark(SIMD_SCALAR1);
    quick_scan_benchmark(SIMD_SWAR);
#ifdef SIMD_NEON64
    quick_scan_benchmark(SIMD_NEON64);
#endif
#ifdef SIMD_SVE2
    quick_benchmark(SIMD_SVE2);
#endif
        
    return 0;
}
