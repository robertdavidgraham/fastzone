#ifndef ZONE_SLOW_HEADER_H
#define ZONE_SLOW_HEADER_H
#include <stddef.h>
#include <stdint.h>

struct wire_record_t;

size_t
zone_slow_header(const char *data, size_t cursor, size_t max,
                  struct wire_record_t *out,
                 unsigned *depth);


#endif

