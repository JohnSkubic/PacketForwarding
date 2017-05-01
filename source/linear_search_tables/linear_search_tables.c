/*
 *
 *  Created By: John Skubic 
 *
 *  Description: Basic linear search.  Allows testing of a naive approach against our algorithms.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "utility.h"
#include "linear_search_tables.h"

int main (int argc, char *argv[]) {
  route_table_entry_t *table;
  route_table_entry_t *trace;
  int num_tests, num_entries;
  int i = 0;
  
  if (argc < 3) {
    printf("Usage: %s <filter_file> <trace_file>\n", argv[0]);
    return EXIT_FAILURE;
  }


  /* Build Routing Table */

  if((table = create_routing_table(argv[1], &num_entries)) == NULL) {
    printf("Error: Could not create routing table from file %s\n", argv[1]);
  }

  printf("Found %d unique IP entries\n", num_entries);

  /* Sort Routing Table */

  //Sort Routing Table (Mergesort)
  mergesort(table, num_entries, IP_ADDR);
  mergesort(table, num_entries, MASK_LEN);
  for (i=0; i < num_entries-1; i++) {
    if (table[i].dest_addr.mask < table[i+1].dest_addr.mask) {
      printf("Error at idx: %d\n", i);
      return EXIT_FAILURE;
    } 
  }

  /* Build Trace Array with Gold Outputs */
  if((trace = create_trace(argv[2], table, num_entries, &num_tests)) == NULL) {
    printf("Error: Could not create trace from file %s\n", argv[2]);
  }

  /* Test Routing Table implementation */

  // build routing table structure from table
  mergesort(table, num_entries, IP_ADDR);
  mergesort(table, num_entries, MASK_LEN);
  linear_table_t l_table;
  l_table.size = num_entries;
  l_table.table = table;

  printf("Linear Table Size: %ld Bytes", sizeof(linear_table_t*) + (num_entries * (sizeof(uint32_t) *2)));

  // Run test (second argument is function pointer)
  test_routing_table(trace, num_tests, (void*)&l_table, lookup_small_table);

  /* Free Resources */
  return EXIT_SUCCESS;
}


uint32_t lookup_small_table(uint32_t dest_ip, void *table) {
  linear_table_t *l_table;
  route_table_entry_t rte;
  int i;
  int masks[32];

  masks[0] = 0x80000000;
  for(i = 1; i < 32; i++) {
    masks[i] = (masks[i-1] >> 1) | 0x80000000;
  }

  l_table = (linear_table_t *)table;

  for (i = 0; i < l_table->size; i++) {
    rte = l_table->table[i];
    if ((rte.dest_addr.address & masks[rte.dest_addr.mask-1]) == (dest_ip & masks[rte.dest_addr.mask-1]))
      return rte.next_hop_addr;
  }

  return -1; 
}

