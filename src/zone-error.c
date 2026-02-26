#include "zone-error.h"

#define XXXX(x) case ZONE_ERROR_##x: return #x

const char *zone_error_msg(enum zone_error err) {
    switch (err) {
        //case ZONE_ERROR_BAD_TTL: return "bad TTL";
        XXXX(IMPOSSIBLE);
        XXXX(BAD_TTL);
        XXXX(NESTED_PARENS);
        XXXX(BAD_PARENS);
        XXXX(ORIGIN_LONG);
        XXXX(NAKED_CR);
        XXXX(UNEXPECTED_TOKEN);
        XXXX(DIRECTIVE_UNKNOWN);
        XXXX(EXPECTED_WHITESPACE);
        XXXX(INCLUDE_DEPTH);
        XXXX(INCLUDE_FILENAME_MISSING);
        XXXX(QUOTES_UNTERMINATED);
        XXXX(PARENS_UNTERMINATED);
        XXXX(RECORD_TOO_BIG);
        XXXX(WIRE_OVERFLOW);
        XXXX(EXPECTED_GENERIC);
        XXXX(LABEL_EMPTY); /* like www..exampe.com */
        XXXX(LABEL_LONG); /* over 63 characters */
        XXXX(NAME_LONG); /* over 255 characters */
        XXXX(ESCAPE_BAD); /* \DDD incorrect */
        XXXX(TEXT_MISSING_QUOTES); /* end string quotes not found */
        XXXX(TEXT_LONG);
    default: return "unknown";
    }
}
