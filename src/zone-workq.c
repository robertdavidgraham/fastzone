#include "zone-workq.h"
#include "zone-scan.h"
#include <string.h>

void
zone_workq_add(struct zone_workq *q, struct zone_block *b)
{
    b->next = NULL;

    if (q->tail) {
        q->tail->next = b;
    } else {
        /* empty queue */
        q->head = b;
    }

    q->tail = b;
    q->length++;
}


struct zone_block *
zone_workq_remove(struct zone_workq *q)
{
    struct zone_block *b = q->head;

    if (!b)
        return NULL;

    q->head = b->next;

    if (!q->head)
        q->tail = NULL;

    b->next = NULL; /* poison / safety */
    q->length--;
    return b;
}

void
zone_workq_init(struct zone_workq *wq) {
    memset(wq, 0, sizeof(*wq));
}

void
zone_workq_free(struct zone_workq *wq) {
    memset(wq, 0, sizeof(*wq));
}


