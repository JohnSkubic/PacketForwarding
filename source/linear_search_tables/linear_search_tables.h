/*
 *
 *  Created By: John Skubic 
 *
 *  Description: Basic Linear Search.  
 *
 */

#ifndef LINEAR_SEARCH_TABLES_H 
#define LINEAR_SEARCH_TABLES_H 

#include "utility.h"

typedef struct linear_table_t {
  route_table_entry_t *table;
  int size;
} linear_table_t;

uint32_t lookup_small_table(uint32_t dest_ip, void *table);

#endif //LINEAR_SEARCH_TABLES_H
