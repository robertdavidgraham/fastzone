#include "zone-scan.h"
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>

/**
 * Sets the current line number and character number for later error reporting,
 * so that we can know where errors occur.
 */
static void
block_newline(zone_block_t *block, size_t offset) {
    block->line_number_now++;
    block->line_offset_start = offset;
}

/**
 * Set the error code of which error we found and stop further
 * parsing.
 */
static size_t
block_error(zone_block_t *block, size_t offset, size_t max, enum zone_error err) {
    block->is_error_seen = 1;
    block->error_code = err; /* e.g. ZONE_ERROR_BAD_TTL */
    block->error_line_offset = offset - block->line_offset_start;
    block->error_line_number = block->line_number_now;
    return max + 1;
}

/**
 * Return a notification to stop further processing of this block, due to falling off the
 * end of the buffer mid parsing.
 */
size_t block_frag(zone_block_t *block, size_t pos, size_t len) {
    return len + 1;
}

int block_append(zone_block_t *block, const char *data, size_t offset, size_t next) {
    if (block->is_full)
        return 1;
    
    static const size_t block_max = sizeof(block->buf);
    
    size_t length = next - offset;
    
    if (block->record_ptr + length > block_max) {
        /* */
        block->is_full = 1;
        return 1;
    }
    
    memcpy(block->buf + block->record_ptr, data+offset, length);
    block->record_ptr += length;
    block->records[block->record_count].contents_length += length;

    return 0;
}

/**
 * When we see an newline '\n', we should also handle a preceding
 * carriage-return '\r' if it existed.
 */
int block_fix_cr(zone_block_t *block) {
    return 0;
}

int block_name_repeat(zone_block_t *block, size_t offset, size_t next) {
    //static const size_t block_max = sizeof(block->buf);
    static const size_t record_max = sizeof(block->records)/sizeof(block->records[0]);
    
    if (block->is_full)
        return 1;

    if (block->record_count >= record_max) {
        block->is_full = 1;
        return 1;
    }

    zone_block_record_t *record = &block->records[block->record_count];

    /* Fill in the entry */
    record->name = block->last_name;
    record->name_length = block->last_name_length;
    record->contents_offset = block->record_ptr;
    record->contents_length = 0;

    return 0;
}

int block_add_name(zone_block_t *block, const char *data, size_t offset, size_t next) {
    static const size_t block_max = sizeof(block->buf);
    static const size_t record_max = sizeof(block->records)/sizeof(block->records[0]);
    size_t length = next - offset;
    
    
    if (block->is_full)
        return 1;
    
    /* Make sure we aren't full yet */
    if (block->record_ptr + length + 3 > block_max) {
        block->is_full = 1;
        return 1;
    }
    if (block->record_count >= record_max) {
        block->is_full = 1;
        return 1;
    }


    zone_block_record_t *record = &block->records[block->record_count];

    
    memcpy(block->buf + block->record_ptr, data+offset, length);
    record->name = block->buf + block->record_ptr;
    record->name_length = length;
    
    block->record_ptr += length;
    
    record->contents_offset = block->record_ptr;
    record->contents_length = 0;
    
    block->last_name = record->name;
    block->last_name_length = record->name_length;
    
    return 0;
}

#define CHECK_FRAG(b,o,m) if (o >= m) return block_frag(b,o,m)


// Find closing paren (must handle quotes and comments)
static inline size_t
find_close_paren(const char *data, size_t offset, size_t max, zone_block_t *block) {
    
    while (offset < max) {
        
        /* Scan very fast to either the end-of-line or a trigger character
         * that has to be handled specially */
        offset = zone_scan_fast2(data, offset, max);
        CHECK_FRAG(block, offset, max);
        
        char c = data[offset];
        
        if (c == ')') {
            block->is_inside_parens = 0;
            offset++;
            CHECK_FRAG(block, offset, max);
            ((char*)data)[offset-1] = ' ';
            return offset;
        }
        
        if (c == '(') {
            /* nested parentheses error */
            return block_error(block, offset, max, ZONE_ERROR_NESTED_PARENS);
        }

        if (c == '"') {            
            /* Quoted string */
            block->quote_line_offset = offset;

            offset = zone_scan_quote(data, offset + 1, max);
            CHECK_FRAG(block, offset, max);
            
            c = data[offset];
            if (c == '"') {
                offset++;
                CHECK_FRAG(block, offset, max);
            } else if (c == '\n') {
                offset = block->quote_line_offset;
                return block_error(block, offset, max, ZONE_ERROR_QUOTES_UNTERMINATED);
            } else {
                assert(c == '"');
            }
            
            /* It must be followed by whitespace */
            c = data[offset];
            if (c == ' ' || c == '\t' || c == ';' || c == '(' || c == '\r' || c == '\n')
                continue;
            else {
                return block_error(block, offset, max, ZONE_ERROR_EXPECTED_WHITESPACE);
            }
        }
        
        if (c == '\\') {
            /* Backslash escape */
            offset = zone_scan_escape(data, offset, max);
            CHECK_FRAG(block, offset, max);
            continue;
        }
        
        if (c == ';') {
            /* Comment: effectively end-of-line */
            offset = zone_scan_eol(data, offset, max);
            CHECK_FRAG(block, offset, max);
            c = data[offset];
            /* fall through to end-of-line parsing */
        }
        
        if (c == '\n') {
            offset++;
            CHECK_FRAG(block, offset, max);
            if (offset >= 2 && data[offset-2] == '\r')
                ((char*)data)[offset-2] = ' ';
            block_newline(block, offset);
            continue;
        }
        
        assert(!"impossible");
        return block_error(block, offset, max, ZONE_ERROR_IMPOSSIBLE);
    }
    assert(!"impossible");
    return block_error(block, offset, max, ZONE_ERROR_IMPOSSIBLE);
}

static inline size_t
find_open_paren(const char *data, size_t offset, size_t max, zone_block_t *block) {
    
    while (offset < max) {
        
        if (block->is_error_seen)
            return max + 1;
        
        size_t next;
        
        next = zone_scan_fast(data, offset, max);
        CHECK_FRAG(block, next, max);
        //block_append(block, data, offset, next);
        offset = next;
                
        char c = data[offset];

        if (c == '(') {
            block->is_inside_parens = 1;
            block->parens_line_number = block->line_number_now;
            block->parens_line_offset = offset - block->line_offset_start;

            offset++;
            CHECK_FRAG(block, offset, max);
            ((char*)data)[offset-1] = ' ';
            
            offset = find_close_paren(data, offset, max, block);
            CHECK_FRAG(block, offset, max);
            continue;
        }
        
        if (c == '"') {
            /* Quoted string */
            block->quote_line_offset = offset;

            offset = zone_scan_quote(data, offset + 1, max);
            CHECK_FRAG(block, offset, max);
            
            c = data[offset];
            if (c == '"') {
                offset++;
                CHECK_FRAG(block, offset, max);
            } else if (c == '\n') {
                offset = block->quote_line_offset;
                return block_error(block, offset, max, ZONE_ERROR_QUOTES_UNTERMINATED);
            } else {
                assert(c == '"');
            }
            
            /* It must be followed by whitespace */
            c = data[offset];
            if (c == ' ' || c == '\t' || c == ';' || c == '(' || c == '\r' || c == '\n')
                continue;
            else {
                return block_error(block, offset, max, ZONE_ERROR_EXPECTED_WHITESPACE);
            }
        }
        
        if (c == '\\') {
            /* Backslash escape */
            offset = zone_scan_escape(data, offset, max);
            CHECK_FRAG(block, offset, max);
            continue;
        }
        
        if (c == ';') {
            offset = zone_scan_eol(data, offset, max);
            CHECK_FRAG(block, offset, max);
            c = data[offset];
            /* fall through to end-of-line parsing */
        }
        
        if (c == '\n') {
            offset++;
            CHECK_FRAG(block, next, max);
            if (offset >= 2 && data[offset-2] == '\r')
                ((char*)data)[offset-2] = ' ';
            block_newline(block, offset);
            return offset;
        }
        
        if (c == ')') {
            return block_error(block, offset, max, ZONE_ERROR_BAD_PARENS);
        } else {
            assert(!"impossible");
            return block_error(block, offset, max, ZONE_ERROR_IMPOSSIBLE);
        }
    }
    return offset;
}

static inline size_t zone_skip_space(const  char *data, size_t pos, size_t len) {
    while (data[pos] == ' ' || data[pos] == '\t')
        pos++;
    return pos;
}

static size_t handle_ORIGIN(zone_block_t *block, const char *data, size_t offset, size_t max) {
    size_t next = zone_scan_name(data, offset, max);
    CHECK_FRAG(block, next, max);
    size_t name_len = next-offset;
    
    if (data[next - 1] != '.') {
        /* We have a relative $ORIGIN, so append */
        if (block->origin_length + name_len > sizeof(block->origin)-1) {
            /* origin name too long */
            return block_error(block, offset, max, ZONE_ERROR_ORIGIN_LONG);
        }
    } else {
        block->origin_length = 0;
    }
    memcpy(block->origin + block->origin_length,
           data + offset,
           name_len);
    block->origin[block->origin_length + name_len] = '\0';
    offset = next;
    
    offset = zone_skip_space(data, offset, max);
    CHECK_FRAG(block, next, max);
    
    if (data[offset] == ';') {
        offset = zone_scan_eol(data, offset, max);
        CHECK_FRAG(block, offset, max);
        block_newline(block, offset);
    }
    
    if (data[offset] == '\n') {
        offset++;
        CHECK_FRAG(block, offset, max);
        block_newline(block, offset);
    } else if (data[offset] == '\r') {
        offset++;
        CHECK_FRAG(block, offset, max);
        if (data[offset] != '\n')
            return block_error(block, offset, max, ZONE_ERROR_NAKED_CR);
        offset++;
        CHECK_FRAG(block, offset, max);
        block_newline(block, offset);
    }  else
        return block_error(block, offset, max, ZONE_ERROR_UNEXPECTED_TOKEN);

    return offset;
}

/**
 * My version of "isdigit()" to avoid locale issues with normal isdigit().
 * I think the standard way is a big static lookup table with 256 entries.
 * I'm too lazy for that, and am instead doing a "branchless" version.
 */
static inline int my_isdigit(char x) {
    unsigned char c = (unsigned  char)x;
    unsigned char lo = c - '0';    // underflows → MSB=1 if c < '0'
    unsigned char hi = '9' + 1 - c; // underflows → MSB=1 if c > '9'
    unsigned char bad = (lo | hi) & 0x80;
    return (bad >> 7) ^ 1;   // 1 if digit, 0 otherwise
}

static size_t handle_TTL(zone_block_t *block, const char *data, size_t offset, size_t max) {
    size_t next = zone_scan_nospace(data, offset, max);
    CHECK_FRAG(block, next, max);

    uint64_t num;
    uint64_t seconds = 0;
    static const uint64_t MAX_TTL = 2147483647; /*2^32-1, per RFC 2181 */
    
again:
    num = 0;
    
    /* First character of the token must be a digit */
    if (!my_isdigit(data[offset]))
        return block_error(block, offset, max, ZONE_ERROR_BAD_TTL);
    
    /* Parse the numeric portion */
    while (offset < next && my_isdigit(data[offset])) {
        num = num * 10 + (data[offset++] - '0');
        if (num > MAX_TTL)
            return block_error(block, offset, max, ZONE_ERROR_BAD_TTL);
    }
    
    /*W (weeks), D (days), H (hours), M (minutes), and S (seconds) */
    if (offset < next) {
        switch (data[offset]) {
        case 's': case 'S': /* seconds */
            num *= 1;
            break;
        case 'm': case 'M': /* minutes */
            num *= 60;
            break;
        case 'h': case 'H': /* hour */
            num *= 60 * 60;
            break;
        case 'd': case 'D': /* day */
            num *= 60 * 60 * 24;
            break;
        case 'w': case 'W': /* week */
            num *= 60 * 60 * 24 * 7;
            break;
        default:
            return block_error(block, offset, max, ZONE_ERROR_BAD_TTL);
        }
        offset++;
    }
    seconds += num;
    if (seconds >= MAX_TTL)
        return block_error(block, offset, max, ZONE_ERROR_BAD_TTL);
    
    /* Multiple specifications can be added up, like 1d12h */
    if (offset < next)
        goto again;
    
    offset = next;
    

    offset = zone_skip_space(data, offset, max);
    CHECK_FRAG(block, next, max);
    
    if (data[offset] == ';') {
        offset = zone_scan_eol(data, offset, max);
        CHECK_FRAG(block, offset, max);
        block_newline(block, offset);
    }
    if (data[offset] == '\n') {
        offset++;
        CHECK_FRAG(block, offset, max);
        block_newline(block, offset);
    } else if (data[offset] == '\r') {
        offset++;
        CHECK_FRAG(block, offset, max);
        if (data[offset] != '\n')
            return block_error(block, offset, max, ZONE_ERROR_NAKED_CR);
        offset++;
        CHECK_FRAG(block, offset, max);
        block_newline(block, offset);
    } else
        return block_error(block, offset, max, ZONE_ERROR_UNEXPECTED_TOKEN);

    return offset;
}
static size_t handle_INCLUDE(zone_block_t *block, const char *data, size_t offset, size_t max) {
    size_t next = zone_scan_nospace(data, offset, max);
    CHECK_FRAG(block, next, max);
    size_t len = next - offset;
    
    
    /* Write this filename to the block. We'll
     * immediately return so that the caller\
     * can process this file */
    block->include.filename = malloc(len + 1);
    memcpy(block->include.filename, data + offset, len);
    block->include.filename[len] = '\0';
    block->include.filename_length = len;

    
    offset = zone_skip_space(data, offset, max);
    CHECK_FRAG(block, offset, max);
    
    if (data[offset] == ';') {
        offset = zone_scan_eol(data, offset, max);
        CHECK_FRAG(block, offset, max);
        block_newline(block, offset);
    }
    
    if (data[offset] == '\n') {
        offset++;
        CHECK_FRAG(block, offset, max);
        block_newline(block, offset);
    } else if (data[offset] == '\r') {
        offset++;
        CHECK_FRAG(block, offset, max);
        if (data[offset] != '\n')
            return block_error(block, offset, max, ZONE_ERROR_NAKED_CR);
        offset++;
        CHECK_FRAG(block, offset, max);
        block_newline(block, offset);
    } else
        return block_error(block, offset, max, ZONE_ERROR_UNEXPECTED_TOKEN);
    
    /* We for a return to the caller immediately so that
     * they can do the actual include */
    block->is_include = 1;
    return max + 1;
}
static size_t handle_GENERATE(zone_block_t *block, const char *data, size_t offset, size_t max) {
    return block_error(block, offset, max, ZONE_ERROR_DIRECTIVE_UNKNOWN);
}

/**
 * Create my own tolower() to avoid locale issues.
 */
static int my_tolower(int c) {
    if (c >= 'A' && c <= 'Z') {
        return c + 32;  // ASCII 'A'(65) to 'Z'(90) become 'a'(97) to 'z'(122)
    }
    return c;  // Non-uppercase unchanged
}

/**
 * Does the string start with a prefix like $ORIGIN or $TTL.
 */
static inline int is_prefix(const char *lhs, const char *rhs, size_t offset, size_t max) {
    size_t i;
    for (i=0; lhs[i]; i++) {
        if (my_tolower(lhs[i]) != my_tolower(rhs[offset+i]))
            return 0;
    }
    return 1;
}
// Parse record: handles fast path and special characters
static size_t scan_records(zone_block_t *block, const char *data, size_t cursor, size_t max) {
    int is_leading_space;
    size_t next;
again:
    if (block->is_error_seen || block->is_full)
        return max + 1;
    
    block->line_offset_start = cursor;

    /* If there's leading space on this record, we repeat the previous
     * owner name */
    is_leading_space = 0;
    
    
    /* Strip any leading whitespace on the line */
    if (data[cursor] == ' ' || data[cursor] == '\t') {
        cursor = zone_skip_space(data, cursor, max);
        CHECK_FRAG(block, cursor, max);
        is_leading_space = 1; /* remember for down below */
    }
    
    /* If a directive, then we need to parse that immediately */
    if (data[cursor] == '$') {
        /* Only allow such directives at the start
         * of a block. We will emite an artifical
         * "full" message to force this block
         * to end and a new block to start. One the new
         * block, this will be the first line. */
        if (block->record_count) {
            block->is_full = 1;
            return max + 1;
        }
        
        /* Grab the directive string like "$ORIGIN" */
        next = zone_scan_nospace(data, cursor, max);
        CHECK_FRAG(block, next, max);
        size_t directive = cursor;
        size_t directive_length = next - cursor;
        cursor = next;
        cursor = zone_skip_space(data, cursor, max);
        CHECK_FRAG(block, next, max);
        
        if (is_prefix("$ORIGIN", data, directive, directive_length)) {
            cursor = handle_ORIGIN(block, data, cursor, max);
            CHECK_FRAG(block, cursor, max);
        } else if (is_prefix("$TTL", data, directive, directive_length)) {
            cursor = handle_TTL(block, data, cursor, max);
            CHECK_FRAG(block, cursor, max);
        } else if (is_prefix("$INCLUDE", data, directive, directive_length)) {
            cursor = handle_INCLUDE(block, data, cursor, max);
            CHECK_FRAG(block, cursor, max);
        } else if (is_prefix("$GENERATE", data, directive, directive_length)) {
            cursor = handle_GENERATE(block, data, cursor, max);
            CHECK_FRAG(block, cursor, max);
        } else {
            return block_error(block, cursor, max, ZONE_ERROR_DIRECTIVE_UNKNOWN);
        }
        goto again;
    }
    
    /* If the line consists only of a comment, then skip
     * this entire line */
    if (data[cursor] == ';') {
        cursor = zone_scan_eol(data, cursor, max);
        CHECK_FRAG(block, cursor, max);
    }
    
    /* Check for CRLF end of line */
    if (data[cursor] == '\r') {
        cursor++;
        CHECK_FRAG(block, cursor, max);
        
        if (data[cursor] != '\n')
            return block_error(block, cursor, max, ZONE_ERROR_NAKED_CR);
        cursor++;
        CHECK_FRAG(block, cursor, max);
        block_newline(block, cursor);
        goto again;
    }
    
    /* Check for LF end of line */
    if (data[cursor] == '\n') {
        cursor++;
        CHECK_FRAG(block, cursor, max);
        block_newline(block, cursor);
        goto again;
    }
    
    /* The default case is that we have a name, so
     * process that name*/
    if (is_leading_space) {
        /* no name, just repeat last one */
        block_name_repeat(block, cursor, max);
    } else {
        next = zone_scan_nospace(data, cursor, max);
        CHECK_FRAG(block, next, max);
        block_add_name(block, data, cursor, next);
        cursor = next;

        cursor = zone_skip_space(data, cursor, max);
        CHECK_FRAG(block, cursor, max);
    }
    
    /*
     * Now we process the contents of the record, which consists
     * mostly of dealing with any parenstheses that might appear.
     */
    block->records[block->record_count].contents_offset = cursor; /* start contents */
    cursor = find_open_paren(data, cursor, max, block);
    if (cursor > max)
        return max + 1;

    if (block->is_error_seen || block->is_full)
        return max + 1;

    /* Track everything that has been successfully parsed up to this point,
     * so that we can discard any work after this point if it ends up being
     * a fragment. */
    block->buf_consumed = cursor;
    block->lines_consumed = block->line_number_now;

    /*
     * Create a new record
     */
    static const size_t MAX_RECORDS = sizeof(block->records)/sizeof(block->records[0]);
    if (block->record_count >= MAX_RECORDS) {
        block->is_full = 1;
        return max + 1;
    }
    size_t contents_offset = block->records[block->record_count].contents_offset;
    zone_block_record_t *record = &block->records[block->record_count++];
    record->contents_length = cursor - contents_offset;
    
    if (cursor >= max)
        return cursor;

    goto again;
    
    return cursor;
}

size_t zone_block_fill(zone_block_t *block, const char *data, size_t offset, size_t max) {
    size_t length = max - offset;
    if (length > sizeof(block->buf) - block->buf_max)
        length = sizeof(block->buf) - block->buf_max;
    
    memcpy(block->buf + block->buf_max, data + offset,  length);
    
    /* may overflow from `buf` into `prep_zone`, that's the idea */
    memcpy(block->buf + block->buf_max + length, "\n \n", 4);
    
    block->buf_max += length;
    return offset + length;
}

int zone_block_scan(zone_block_t *block) {

    const char *data = block->buf;
    size_t cursor = 0;
    size_t max = block->buf_max;
    
    
    cursor = scan_records(block, data, cursor, max);
    
    if (block->is_error_seen)
        return BLOCK_ERROR;
    if (block->is_include)
        return BLOCK_INCLUDE;
    
    assert(cursor >= max);
    
    /* If we reach the end of the buffer, but haven't actually consumed
     * any, then we have eitehr a really huge record too big for the
     * internal buffer, or we have an unbound parentheses, where there's
     * no ending parentheses. If that happened, the previous block
     * was terminated and we are rescanning this condition. */
    if (block->buf_consumed == 0) {
        block->error_line_number = block->line_number_now;
        block->error_line_offset = block->line_offset_start - cursor;
        block->error_code = ZONE_ERROR_RECORD_TOO_BIG;
        return BLOCK_ERROR;
    }

    return BLOCK_OK;
}

zone_block_t *
zone_block_create(const char *filename, const char *origin, unsigned ttl, char is_ttl_seen) {
    zone_block_t *block;
    size_t origin_length = origin?strlen(origin):0;
    
    block = malloc(sizeof(*block));
    
    /* Only zero out the bare minimum */
    memset(block, 0, offsetof(zone_block_t, zeroing_offset));
    
    block->filename = strdup(filename);
    
    if (origin_length && origin_length + 1 < sizeof(block->origin)) {
        block->is_origin_seen = 1;
        memcpy(block->origin, origin, origin_length+1);
    } else
        block->origin[0] = '\0';
    
    if (is_ttl_seen) {
        block->is_ttl_seen = 1;
        block->ttl = ttl;
    }
    
    return block;
}

void
zone_block_free(zone_block_t *block) {
    free(block);
}


zone_block_t *
zone_block_next(zone_block_t *prev) {
    zone_block_t *next;
    
    next = zone_block_create(prev->filename, prev->origin, prev->ttl, prev->is_ttl_seen);
    next->line_number_now = prev->lines_consumed;
    next->lines_consumed = prev->lines_consumed;
    next->total_bytes = prev->total_bytes;
    
    char *unconsumed = prev->buf + prev->buf_consumed;
    size_t length = prev->buf_max - prev->buf_consumed;
    zone_block_fill(next, unconsumed, 0, length);
    return next;
}


void
zone_scan_init(simd_backend_t backend) {
    zone_scan_name_init(backend);
    zone_scan_eol_init(backend);
    //zone_scan_esc_init(backend);
    zone_scan_quote_init(backend);
    zone_scan_space_init(backend);
    zone_scan_nospace_init(backend);
    zone_scan_fast_init(backend);

    g_zone_backend = backend;
}


