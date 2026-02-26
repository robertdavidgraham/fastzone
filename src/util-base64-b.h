
#ifndef BASE64DECODE_H
#define BASE64DECODE_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
    BASE64DEC_ERR_NONE            = 0,
    BASE64DEC_ERR_NULL            = 1 << 0,
    BASE64DEC_ERR_INVALID_CHAR    = 1 << 1,
    BASE64DEC_ERR_INVALID_LENGTH  = 1 << 2,
    BASE64DEC_ERR_INVALID_PADDING = 1 << 3
};

/*
  base64decode()

  - Standard Base64: A-Z a-z 0-9 + /
  - Optional '=' padding only in final quantum
  - Skips only ' ' (0x20) and '\t' (0x09)
  - Stops at first non-valid character (not consumed)
  - Absolutely NO output buffer size checks
  - Assumes it is safe to read past end of input by up to 1024 bytes

  Parameters:
    out_len: set to number of bytes written (input value ignored)

  Returns:
    bytes consumed from input (including skipped spaces/tabs)
*/
size_t base64decode(const char *in,
                    size_t in_length,
                    unsigned char *out,
                    size_t *out_len,
                    int *err);

#ifdef __cplusplus
}
#endif

#endif /* BASE64DECODE_H */
