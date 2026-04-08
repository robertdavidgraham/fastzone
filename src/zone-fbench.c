#include "zone-fbench.h"
#include "zone-parse.h"
#include "zone-parse-record.h"
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
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




/**
 * Called from `print_error_line()` to pretty-print characters,
 * to avoid printing binary chara ters, replacing them with a '.'
 */
static void
print_c(char c) {
    if (c == ' ' || c == '\t')
        printf(" ");
    else if (c == '\r')
        ;
    else if (c == '\n')
        printf(" ");
    else if (isprint(c&0xFF))
        printf("%c", c);
    else
        printf(".");
}

/**
 * Print where the error happens on a line.
 */
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

unsigned zone_file_bench(const char *filename, int backend) {
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
    long long bytes_read = read(fd, data, (unsigned)filesize);
    if (bytes_read < (long long)filesize) {
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
    
    for (unsigned n=0; n<1000; n++) {
        /*
         * Initialize the parsing
         */
        zone_state_t state = {0};
        state.ttl = 3600;
        memcpy(state.origin, "\x07" "example" "\x03" "com" "\x00", 13);
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
            size_t next = zone_slow_record(data, cursor, filesize, &state, &out);
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
    printf("Throughput: [%s] %.2f GB/s %.2f Mrec/s\n", simd_current_name(), gbps, mrps);
   
    
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


