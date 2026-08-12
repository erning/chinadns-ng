#pragma once

#include "misc.h"
#include <stdbool.h>
#include <stddef.h>

void local_rr_init(void);

bool local_rr_find(const void *msg, int qnamelen,
    const void **answer, size_t *answer_len, u16 *answer_count);
