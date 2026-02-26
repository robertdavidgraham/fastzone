#ifndef ZONE_WORKQ_H
#define ZONE_WORKQ_H
#include <stddef.h>
#include <stdint.h>
struct zone_block;
typedef struct zone_block zone_block_t;

typedef struct zone_workq {
    zone_block_t *tail;
    zone_block_t *head;
    size_t length;
} zone_workq_t;

void zone_workq_add(struct zone_workq *q, struct zone_block *b);


struct zone_block *zone_workq_remove(struct zone_workq *q);

void zone_workq_init(struct zone_workq *wq);

void zone_workq_free(struct zone_workq *wq);


#endif
