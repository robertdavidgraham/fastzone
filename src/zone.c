#include "zone.h"
#include "zone-parse.h"
#include "zone-scan.h"

void zone_parse_init(int backend) {
    zone_atom_name_init(backend);
    zone_atom_name4_init(backend);
    zone_atom_name5_init(backend);
    zone_atom_mask_init(backend);
    zone_parse_header2_init(backend);
}

extern void zone_atom_ht_init(void);
extern void zone_atom_init(int backend);

void zone_init(int backend) {
    zone_atom_init(backend);
    zone_scan_init(backend);
    zone_parse_init(backend);
    zone_atom_ht_init();
}

