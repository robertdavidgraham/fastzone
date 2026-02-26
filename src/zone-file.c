#include "zone-scan.h"
#include "zone-workq.h"
#include "util-pathname.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#ifdef _WIN32
#define _CRT_NONSTDC_NO_DEPRECATE
#include <io.h>
#else
#include <unistd.h>
#endif
#include <fcntl.h>
#include <sys/stat.h>



int include_directive(zone_block_t *block, zone_workq_t *wq, unsigned depth) {
    
    /* We only allow shallow nesting of $INCLUDE files */
    if (depth > 20) {
        block->error_code = ZONE_ERROR_INCLUDE_DEPTH;
        block->error_line_number = block->line_number_now;
        block->error_line_offset = 0;
        return BLOCK_ERROR;
    }
    
    /* Grab the 'filename' */
    size_t filename_length;
    char *filename;
    if (block->is_include_filename_seen) {
        filename = block->include.filename;
        filename_length = block->include.filename_length;
        block->is_include_filename_seen = 0;
        block->include.filename = 0;
        block->include.filename_length = 0;
    } else {
        block->error_code = ZONE_ERROR_INCLUDE_FILENAME_MISSING;
        block->error_line_number = block->line_number_now;
        block->error_line_offset = 0;
        return BLOCK_ERROR;
    }
    
    /* Grab the origin, if specified */
    size_t origin_length = 0;
    char *origin = NULL;
    if (block->is_include_origin_seen) {
        origin_length = block->include.origin_length;
        origin = block->include.origin;
        block->is_include_origin_seen = 0;
        block->include.origin = 0;
        block->include.origin_length = 0;
    } else {
        origin_length = 0;
        origin = 0;
    }

    /* Grab the TTL from the previous block */
    //unsigned include_ttl = block->ttl;
    //unsigned include_is_ttl_seen = block->is_ttl_seen;
    
    return BLOCK_ERROR;
}


int zone_readfile(struct zone_workq *wq, int fd,
                  uint64_t *total_records, uint64_t *total_bytes,
                  unsigned depth, const char *filename,
                  const char *origin, unsigned ttl, char is_ttl_seen) {
    static const size_t CHUNK_SIZE = 1024*1024; /* megabyte */
    
    /* Create the first block that we are going to use. We'll chain
     * subsequent blocks from this one.*/
    zone_block_t *block = zone_block_create(filename, origin, ttl, is_ttl_seen);
    
    char *data = malloc(CHUNK_SIZE);
    
    for (;;) {
        size_t offset = 0;
        size_t max;
        enum block_result_t result;
        
        /* Read the next chunk from memory */
        max = read(fd, data, CHUNK_SIZE);
        if (max == 0)
            break;
        
        /* Fill the block with as much of this data as we cann*/
        offset = 0;
        while (offset < max) {
            offset = zone_block_fill(block, data, offset, max);
            
            result = zone_block_scan(block);
            *total_bytes += block->buf_consumed;
            *total_records += block->record_count;

            if (result == BLOCK_ERROR) {
                goto fail;
            }
            
            if (result == BLOCK_INCLUDE) {
                include_directive(block, wq, depth + 1);
                continue; /* Continue with existing block */
            }

            if (result == BLOCK_FULL || result == BLOCK_FRAG) {
                
                /* Chain to next block */
                zone_block_t *next = zone_block_next(block);
                
                /* Add block to our work-queue */
                zone_workq_add(wq, block);
                
                /* Now parse the next block */
                block = next;
                continue;
            }
        }
    }
    
    
    return 0;
fail:
    fprintf(stderr, "%s:%lld: parse error\n", block->filename, (long long)block->line_number_now);
    return 1;
}

