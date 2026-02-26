#include "zone-scan.h"
#include "zone-parse.h"
#include "zone-atom-name.h"
#include "zone-atom.h"
#include "zone-token.h"
#include "zone-workq.h"
#include "zone-qbench.h"
#include "zone.h"
#include "zone-parse-record.h"
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#define _CRT_NONSTDC_NO_DEPRECATE
#include <io.h>
#else
#include <unistd.h>
#endif
#include <fcntl.h>
#include <sys/stat.h>



#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>


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
    printf("Backend: %s\n", simd_get_name());
    close(fd);
    return 0;
}





#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>

static void
print_c(char c) {
    if (c == ' ' || c == '\t')
        printf(" ");
    else if (c == '\r')
        ;
    else if (c == '\n')
        printf(" ");
    else if (isprint(c))
        printf("%c", c);
    else
        printf(".");
}
static void
print_error_line(const char *data, size_t start, size_t err_cursor) {
    size_t i;
    for (i=start; i<err_cursor; i++) {
        print_c(data[i]);
    }
    for (; data[i] != '\n'; i++) {
        print_c(data[i]);
    }
    printf("\n");
    for (i=start; i<err_cursor; i++) {
        printf(" ");
    }
    printf("^\n");
    
}
unsigned rrtypes[65536] = {0};
uint64_t rrbytes[65536] = {0};


unsigned parse_file(const char *filename) {
  
    /*
     * Open the file
     */
    int fd = open(filename, O_RDONLY);
    if (fd == -1) {
        perror(filename);
        return 0;
    }
    
    /*
     * Allocate a buffer to hold it in memory
     */
    struct stat st;
    int err = fstat(fd, &st);
    if (err) {
        perror(filename);
        close(fd);
        return 0;
    }
    size_t filesize = st.st_size;
    char *data = malloc(filesize + 1024);
    if (data == NULL) {
        perror(filename);
        close(fd);
        return 0;
    }
    
    /*
     * Read in the contents
     */
    long long bytes_read = read(fd, data, filesize);
    if (bytes_read < filesize) {
        perror(filename);
        close(fd);
        return 0;
    }
    memcpy(data + filesize, "\n \r\n \n", 6);
    
    
    /*
     * START
     */
    struct timeval start, end;
    uint64_t total_bytes = 0;
    gettimeofday(&start, NULL);
    uint64_t total_records = 0;
    
    for (unsigned n=0; n<5000; n++) {
        /*
         * Initialize the parsing
         */
        zone_state_t state = {0};
        state.ttl = 3600;
        memcpy(state.origin, "\x07example\x03com\x00", 13);
        state.origin_length = 13;
        wire_record_t out = {0};
        out.state.origin = state.origin;
        out.state.origin_length = state.origin_length;
        out.state.default_ttl = 3600;
        out.wire.buf = malloc(128*1024);
        out.wire.max = 64*1024;
        
        size_t cursor;
        for (cursor = 0; cursor<filesize; ) {
            size_t start = cursor;
            out.wire.len = 0;
            size_t next = zone_parse_record(data, cursor, filesize, &state, &out);
            if (out.err.code) {
                fprintf(stderr, "filename:%u: error #%d (%s)\n", (unsigned)state.line_number, out.err.code,
                        zone_error_msg(out.err.code));
                print_error_line(data, start, out.err.cursor);
                exit(1);
            }
            if (out.wire.len) {
                /*printf("%8u: type=%u (%s) len=%u\n",
                 (unsigned)state.line_number,
                 out.rrtype.value,
                 zone_name_from_type(out.rrtype.value),
                 (unsigned)out.wire.len);
                 */
                rrtypes[out.rrtype.value]++;
                rrbytes[out.rrtype.value] += next - cursor;
            }
            total_records++;
            cursor = next;
        }
        total_bytes += filesize;
        
    }
    
    /*
     * STOP
     */
    gettimeofday(&end, NULL);
    double elapsed = (end.tv_sec - start.tv_sec) +
                    (end.tv_usec - start.tv_usec) / 1000000.0;
    double gbps = (total_bytes / (1024.0 * 1024.0 * 1024.0)) / elapsed;
    double mrps = (total_records / elapsed) / 1000000.0;
    printf("Throughput: [%s] %.2f GB/s %.2f Mrec/s\n", simd_get_name(), gbps, mrps);
   
    
    for (unsigned i=0; i<65536; i++) {
        unsigned count = rrtypes[i];
        unsigned long long bytecount = rrbytes[i];
        if (count) {
            printf("%6s - %8u-records %10llu-bytes\n", zone_name_from_type(i), count, bytecount);
        }
    }
    
    close(fd);
    return 0;
}

extern void
zone_types2_init(void);

extern void zone_atom_ttl_bench(void);
int main(int argc, char *argv[]) {
    /*
     * WARNING: don't start reading the code here, read the
     * README.md file first.
     */
    //zone_atom_ttl_bench();
    //return 0;
    zone_init(SIMD_AVX2);

    
    zone_types2_init();
    
    int err = 0;
    //err += zone_parse_header2_quicktest();
    err += zone_atom_quicktest();
    err += zone_parse_header_quicktest();
    err += zone_parse_quicktest();
    if (err)
        fprintf(stderr, "[-] selftest failed\n");
    
    if (argc > 1) {
        parse_file(argv[1]);
    } else {
        parse_file("rrsig.se.zone");
    }
                   
    return 0;
    
    //err += zone_atom_mask_quicktest();
    
    /* zone_init(SIMD_NEON);
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
    quick_parse_name1_benchmark(SIMD_SCALAR);
    quick_parse_name1_benchmark(SIMD_SWAR);
#ifdef SIMD_NEON
    quick_parse_name1_benchmark(SIMD_NEON);
#endif
#ifdef SIMD_SVE2
    quick_parse_name1_benchmark(SIMD_SVE2);
#endif

    quick_parse_name2_benchmark(SIMD_SCALAR);
    quick_parse_name2_benchmark(SIMD_SWAR);
#ifdef SIMD_NEON
    quick_parse_name2_benchmark(SIMD_NEON);
#endif
#ifdef SIMD_SVE2
    quick_parse_name2_benchmark(SIMD_SVE2);
#endif

    quick_parse_name3_benchmark(SIMD_SCALAR);
    quick_parse_name3_benchmark(SIMD_SWAR);
#ifdef SIMD_NEON
    quick_parse_name3_benchmark(SIMD_NEON);
#endif
#ifdef SIMD_SVE2
    quick_parse_name3_benchmark(SIMD_SVE2);
#endif
#endif
    
    quick_parse_name4_benchmark(SIMD_SCALAR);
    //quick_parse_name4_benchmark(SIMD_SWAR);
#ifdef SIMD_NEON
    quick_parse_name4_benchmark(SIMD_NEON);
#endif
#ifdef SIMD_SVE2
    quick_parse_name4_benchmark(SIMD_SVE2);
#endif

    quick_parse_name5_benchmark(SIMD_SCALAR);
    quick_parse_name5_benchmark(SIMD_SWAR);
#ifdef SIMD_NEON
    quick_parse_name5_benchmark(SIMD_NEON);
#endif
#ifdef SIMD_SVE2
    quick_parse_name5_benchmark(SIMD_SVE2);
#endif


    /*
     * Do the simplest benchmarks
     */
    quick_scan_benchmark(SIMD_SCALAR);
    quick_scan_benchmark(SIMD_SWAR);
#ifdef SIMD_NEON
    quick_scan_benchmark(SIMD_NEON);
#endif
#ifdef SIMD_SVE2
    quick_benchmark(SIMD_SVE2);
#endif
        
    return 0;
}
