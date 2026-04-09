/* zone-parse-token.h
 *
 * Token/space scanning with persistent SIMD masks.
 *
 * This module maintains a rolling classification window for the bytes starting at
 * the *current* cursor position:
 *
 *   tokens->mask_st : bit i == 1 iff byte i is ' ' or '\t'
 *   tokens->mask_ws : bit i == 1 iff byte i is ' ', '\t', '\r', or '\n'
 *   tokens->avail   : number of valid bits/bytes currently in the masks (0..64)
 *
 * Public API:
 *   - parse_tokens_init(backend): choose SIMD backend at runtime (AUTO picks best)
 *   - parse_tokens_reset(tokens): clear state (start fresh at some cursor)
 *   - parse_token_length(data,cursor,tokens): length until first WS4 (space/tab/cr/nl)
 *   - parse_space_length(data,cursor,tokens): length of run of space/tab only
 *   - parse_token_consume(n,tokens): consume n bytes from current masks/avail
 *
 * Notes:
 *   - The caller typically does: len = parse_token_length(...); cursor += len;
 *     and similarly for parse_space_length().
 *   - parse_token_consume() only consumes from currently-available mask bytes;
 *     it does not refill because it has no pointer. Use parse_*_length() to refill.
 */

#ifndef ZONE_PARSE_TOKEN_H
#define ZONE_PARSE_TOKEN_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* If simd_backend_t is already defined elsewhere in your project, you can include
 * that header instead and remove this forward-decl.
 */
typedef enum zone_backend simd_backend_t;

/* Rolling token classification window. */
typedef struct parsetokens_t {
    uint64_t mask_st; /* space/tab */
    uint64_t mask_ws; /* space/tab/CR/NL */
    unsigned avail;   /* 0..64 */
} parsetokens_t;

/* Initialize the scanner backend (call once at startup, or whenever you want to switch). */
void parse_tokens_init(simd_backend_t backend);

/* Reset/clear rolling state (start fresh at a new cursor). */
static inline void parse_tokens_reset(parsetokens_t *t)
{
    t->mask_st = 0;
    t->mask_ws = 0;
    t->avail   = 0;
}

/* Returns length of token ended by any of: ' ', '\t', '\r', '\n'
 * Consumes that token from the rolling state.
 */
size_t parse_token_length2(const char *data, size_t cursor, parsetokens_t *tokens);

static inline
size_t parse_token_length(const char *data, size_t cursor, parsetokens_t *tokens) {
    unsigned length = ctz64(tokens->mask_ws);
    if (length == 0 || length >= tokens->avail)
        return parse_token_length2(data, cursor, tokens);
    else {
        tokens->mask_st >>= length;
        tokens->mask_ws >>= length;
        tokens->avail    -= length;
        return length;
    }
}


size_t parse_space_length2(const char *data, size_t cursor, parsetokens_t *tokens);

/* Returns length of run of only: ' ', '\t'
 * Consumes that run from the rolling state.
 */
static inline
size_t parse_space_length(const char *data, size_t cursor, parsetokens_t *tokens) {
    unsigned length = ctz64(~tokens->mask_st);
    if (length >= tokens->avail)
        return parse_space_length2(data, cursor, tokens);
    else {
        tokens->mask_st >>= length;
        tokens->mask_ws >>= length;
        tokens->avail    -= length;
        return length;
    }
}

/* Consume an arbitrary number of bytes from the current rolling masks (no refill). */
void parse_token_consume(size_t length, parsetokens_t *tokens);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* ZONE_PARSE_TOKEN_H */
