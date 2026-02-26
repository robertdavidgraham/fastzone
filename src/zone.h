#ifndef ZONE_H
#define ZONE_H

/**
 * Initialize everything, primarily selecting the SIMD backend
 * that we should be using for fast parsing.
 */
void zone_init(int backend);

#endif
