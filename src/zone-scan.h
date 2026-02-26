// dns_parser.h
#ifndef ZONE_SCAN_H
#define ZONE_SCAN_H
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "util-simd.h"
#include "zone-error.h"

typedef struct dns_record_t {
    const char *name;
    size_t name_len;
    size_t name_offset;
    size_t name_line_number;
    const char *data;
    size_t data_len;
    size_t data_offset;
    size_t data_line_number;
} dns_record_t;

typedef struct zone_block_record {
    const char *name;
    size_t contents_offset;
    unsigned short name_length;
    unsigned short contents_length;
} zone_block_record_t;

typedef struct zone_block {
    uint64_t total_bytes;
    uint64_t lines_consumed;
    uint64_t line_number_now;       /* current line we are on, ahead of lines_consumed */
    uint64_t line_offset_start; /* value of cursor at start of line */
    size_t record_count;
    size_t record_ptr;

    
    unsigned char is_error_seen:1;
    unsigned char is_full:1;
    unsigned char is_include:1;
    unsigned char is_origin_seen:1;
    unsigned char is_ttl_seen:1;
    unsigned char is_include_filename_seen:1;
    unsigned char is_include_origin_seen:1;
    unsigned char is_inside_parens:1;
    unsigned char is_inside_quotes:1;
    
    size_t origin_length;
    const char *last_name;
    size_t last_name_length;

    
    /* The end of the last good record we parsed.
     * Everything in the `buf` past this point has not yet been
     * parsed.
     * When moving fragment to new block, everything after this point
     * needs to be copied. */
    size_t buf_consumed;

    /* number of bytes in this buffer */
    size_t buf_max;

    /* -------- everything before here is initialzed to zero ------- */
    unsigned char zeroing_offset;
    /* -------- everything after here is un-initialzed to zero ------- */

    

    /* The filename we are parsing, useful for printing error messages. */
    char *filename;


    /* The work-queue contains a linked list of blocks
     * that workers remove from the head and we insert
     * into the tail. */
    struct zone_block *next;
    
    /* Indicates this block was terminated at
     * the specified line number and character number.
     * Error msgs can be printed with "filename:23:7: bad field"
     * like how GCC/clang work, pointing not only to the line
     * but which character in that line is at fault. */
    size_t error_line_offset;
    size_t error_line_number;
    enum zone_error error_code;

    size_t parens_line_offset;
    size_t parens_line_number;
    size_t quote_line_number;
    size_t quote_line_offset;
    
    /* The value of the last $ORIGIN field we saw.
     * This may be copied over from the previous
     * block. Changing the $ORIGIN causes the
     * current block to be terminated. */
    char origin[1024];

    /* The value of the last $TTL that we've seen.
     * This may be copied over from the previous block.
     * Changing the $TTL causes the current block to
     * be terminated. */
    unsigned ttl;
    
    struct {
        char *filename;
        size_t filename_length;
        char *origin;
        size_t origin_length;
    } include;

    /* Scanned records are placed here. They point back into
     * the `buf` section */
    zone_block_record_t records[1000];

    /* Roughly 100 kilobytes for the memory storing records */
    char buf[100 * 1024];
    char prep_zone[1024];
    
} zone_block_t;



enum block_result_t {
    BLOCK_FULL=0,
    BLOCK_FRAG=0,
    BLOCK_OK=0,
    BLOCK_ERROR,
    BLOCK_INCLUDE,
};

/**
 * Before scanning/parsing a block, we need to fill it with data to parse.
 */
size_t zone_block_fill(zone_block_t *block, const char *data, size_t offset, size_t max);

/**
 * Scan the data within the block, a preprocessing step that finds the boundaries
 * of all the records. This is highly optimized to be FAST and LIMITED as possible,
 * as the processing speed is dictated by this speed of this function.
 * A call to `zone_block_fill()` should've been called to fill the blocks
 * buffer with data to parse.
 */
int zone_block_scan(zone_block_t *block);



void zone_scan_eol_init(simd_backend_t backend);
//void zone_scan_escape_init(SIMD_t backend);
void zone_scan_fast_init(simd_backend_t backend);
void zone_scan_label_init(simd_backend_t backend);
void zone_scan_name_init(simd_backend_t backend);
void zone_scan_quote_init(simd_backend_t backend);
void zone_scan_space_init(simd_backend_t backend);
void zone_scan_nospace_init(simd_backend_t backend);
void zone_scan_init(simd_backend_t backend);

int zone_scan_eol_quicktest(void);
int zone_scan_escape_quicktest(void);
int zone_scan_fast_quicktest(void);
int zone_scan_fast2_quicktest(void);
int zone_scan_label_quicktest(void);
int zone_scan_name_quicktest(void);
int zone_scan_quote_quicktest(void);
int zone_scan_space_quicktest(void);
int zone_scan_nospace_quicktest(void);
int zone_scan_quicktest(void);

extern size_t (*zone_scan_eol)(const char *data, size_t offset, size_t max);
extern size_t zone_scan_escape(const char *data, size_t offset, size_t max);
extern size_t (*zone_scan_fast)(const char *data, size_t offset, size_t len);
extern size_t (*zone_scan_fast2)(const char *data, size_t offset, size_t len);
extern size_t (*zone_scan_label)(const char *data, size_t offset, size_t len);
extern size_t zone_scan_name(const char *data, size_t offset, size_t max);
extern size_t zone_scan_quote(const char *data, size_t offset, size_t max);
extern size_t zone_scan_space(const char *data, size_t offset, size_t len, unsigned *depth);
extern size_t (*zone_scan_nospace)(const char *data, size_t offset, size_t len);


zone_block_t *
zone_block_create(const char *filename, const char *origin, unsigned ttl, char is_ttl_seen);

void
zone_block_free(zone_block_t *block);

zone_block_t *
zone_block_next(zone_block_t *prev);

struct zone_workq;

int zone_readfile(struct zone_workq *wq, int fd,
                  uint64_t *total_records, uint64_t *total_bytes,
                  unsigned depth,
                  const char *filename, const char *origin, unsigned ttl, char is_ttl_seen);

int zone_readbuf(struct zone_workq *wq, const char *buf, size_t length);



#endif


