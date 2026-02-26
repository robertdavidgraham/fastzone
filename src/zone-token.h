#ifndef ZONE_TOKEN_H
#define ZONE_TOKEN_H
#include "util-simd.h"
#include <stddef.h>
#include <stdint.h>

struct rrtype_t;

enum zone_class {
  ZONE_CLASS_NONE = 0,
  ZONE_CLASS_IN   = 1,
  ZONE_CLASS_CH   = 3,
  ZONE_CLASS_HS   = 4,
  ZONE_CLASS_CS   = 2
};

struct zone_span {
  uint32_t off;
  uint32_t len;
};

#define ZONE_MAX_RRTOKENS 64

struct zone_tokenized {
    const struct rrtype_t *rr_type;
    uint32_t ttl_seconds;
    uint16_t rrclass;
    uint8_t  has_ttl;
    uint8_t  has_class;
    
    struct zone_span type_tok;
    
    uint32_t rrtoken_count;
    struct zone_span rrtokens[ZONE_MAX_RRTOKENS];
};

enum zone_rc {
  ZONE_OK = 0,
  ZONE_ERR_SYNTAX = -1,
  ZONE_ERR_UNTERM_QUOTE = -2,
  ZONE_ERR_UNBAL_PARENS = -3,
  ZONE_ERR_BAD_TYPE = -6,
  ZONE_ERR_TOO_MANY_TOKENS = -7,
  ZONE_ERR_EMPTY_TYPE = -8
};

int zone_tokenize(char *rec, size_t maxlen, struct zone_tokenized *out);

/**
 * @return 0 on success, positive integer on failure.
 */
int zone_tokenize_quicktest(void);

void zone_tokenizer_init(simd_backend_t b);

#endif
