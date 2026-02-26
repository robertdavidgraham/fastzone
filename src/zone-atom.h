#ifndef ZONE_ATOM_H
#define ZONE_ATOM_H
#include "zone-parse-record.h"
struct wire_record_t;
size_t zone_atom_ipv4(const char *data, size_t cursor, size_t max, struct wire_record_t *out);
size_t zone_atom_ipv6(const char *data, size_t cursor, size_t max, wire_record_t *out);
size_t zone_atom_int8(const char *data, size_t cursor, size_t max, wire_record_t *out);
size_t zone_atom_int8x(const char *data, size_t cursor, size_t max, wire_record_t *out, unsigned *x);
size_t zone_atom_int16(const char *data, size_t cursor, size_t max, wire_record_t *out);
size_t zone_atom_int32(const char *data, size_t cursor, size_t max, wire_record_t *out);
size_t zone_atom_expire1(const char *data, size_t cursor, size_t max, struct wire_record_t *out);
size_t zone_atom_expire2(const char *data, size_t cursor, size_t max, struct wire_record_t *out);
size_t zone_atom_caaval(const char *data, size_t cursor, size_t max, wire_record_t *out);
size_t zone_atom_txt(const char *data, size_t cursor, size_t max, wire_record_t *out);
size_t zone_atom_txt_list(const char *data, size_t cursor, size_t max, wire_record_t *out, unsigned *depth);
size_t zone_atom_hex_l(const char *data, size_t cursor, size_t max, wire_record_t *out);
size_t zone_atom_hex_c(const char *data, size_t cursor, size_t max, wire_record_t *out);
size_t zone_atom_hexes(const char *data, size_t cursor, size_t max, wire_record_t *out, unsigned *depth);
size_t zone_atom_hexes_c(const char *data, size_t cursor, size_t max, wire_record_t *out, unsigned *depth);
size_t zone_atom_svcparams(const char *data, size_t cursor, size_t max, wire_record_t *out, unsigned *depth);
size_t zone_atom_base64a(const char *data, size_t cursor, size_t max, struct wire_record_t *out, unsigned *depth);
size_t zone_atom_base64b(const char *data, size_t cursor, size_t max, struct wire_record_t *out, unsigned *depth);
size_t zone_atom_base64c(const char *data, size_t cursor, size_t max, struct wire_record_t *out, unsigned *depth);
size_t zone_atom_base64d(const char *data, size_t cursor, size_t max, struct wire_record_t *out, unsigned *depth);
size_t zone_atom_nsec3_hash(const char *data, size_t cursor, size_t max, struct wire_record_t *out);
size_t zone_atom_type(const char *data, size_t cursor, size_t max, struct wire_record_t *out);
size_t zone_atom_bitmap(const char *data, size_t cursor, size_t max, struct wire_record_t *out, unsigned *depth);

size_t zone_parse_finish(const char *data, size_t cursor, size_t max, struct wire_record_t *out, unsigned *depth);
size_t zone_parse_space(const char *data, size_t cursor, size_t max, struct wire_record_t *out, unsigned *depth);

int zone_atom_base64a_quicktest(void);
int zone_atom_base64b_quicktest(void);
int zone_atom_base64c_quicktest(void);
int zone_atom_base64d_quicktest(void);
int zone_atom_ipv6_quicktest(void);
int zone_atom_expire2_quicktest(void);

int zone_atom_quicktest(void);

void
zone_atom_init(int backend);

#endif
