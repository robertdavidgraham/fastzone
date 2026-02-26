#ifndef ZONE_NAME_H
#define ZONE_NAME_H
#include "util-simd.h"
#include "zone-scan.h"
#include <stddef.h>
#include <stdint.h>

struct wire_record_t;

#if 0
size_t
zone_atom_name(const char *data, size_t cursor, size_t max,
                 struct wire_record_t *out);
void zone_atom_name_init(int backend);
#else
#define zone_atom_name zone_parse_name0
#define zone_atom_name_init zone_atom_name4_init
#endif

size_t
zone_parse_name0(const char *data, size_t cursor, size_t max,
                 struct wire_record_t *out);

size_t
zone_atom_name4(const char *data, size_t cursor, size_t max,
                struct wire_record_t *out);


void zone_atom_name4_init(int backend);
void zone_atom_name5_init(int backend);

struct wire_record_t;
struct zone_status_t;

size_t zone_atom_name5(const char *data, size_t i, size_t max, struct wire_record_t *out);

int zone_atom_name4_quicktest(void);
int zone_atom_name5_quicktest(void);

#endif

