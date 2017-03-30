/*
 *
 *  Created By: John Skubic 
 *
 *  Description:
 *
 */

#ifndef SMALL_TABLES_H
#define SMALL_TABLES_H

#include "utility.h"

uint32_t lookup_small_table(uint32_t dest_ip, void *table);

typedef struct small_table_t {
  int todo;
} small_table_t;

#endif
