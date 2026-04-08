#ifndef ZONE_FAST_HEADER_H
#define ZONE_FAST_HEADER_H
#include <stddef.h>
#include <stdint.h>

struct wire_record_t;

/**
 * Parses the first part of a record, the owner-name, TTL, class, and type.
 * This requires that the "classify/index" step must have been performed
 * first. This is "happy-path" parser, anything unexpected causes it to
 * restart parsing and return the results from `zone_slow_header()`.
 * @see zone_slow_header()
 */
size_t
zone_fast_header(const char *data, size_t cursor, size_t max,
                   struct wire_record_t *out,
                 unsigned *depth);

/**
 * Initialize parser with whatever backends it needs. Do this at startup, or
 * during tests/benchmarks when you want to change which backend
 * you are using.
 */
void zone_fast_header_init(int backend);

/**
 * Called on startup, this does a quick unit/regression test of this
 * unit.
 */
int
zone_fast_header_quicktest(int backend);


#endif
