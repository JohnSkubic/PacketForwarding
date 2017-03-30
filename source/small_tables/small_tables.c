/*
 *
 *  Created By: John Skubic 
 *
 *  Description:
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include "utility.h"
#include "small_tables.h"

int main (int argc, char *argv[]) {
  route_table_entry_t *table;
  route_table_entry_t *trace;
  int num_tests;

  if (argc < 3) {
    printf("Usage: %s <filter_file> <trace_file>\n", argv[0]);
    return EXIT_FAILURE;
  }


  /* Build Routing Table */

  if((table = create_routing_table(argv[1])) == NULL) {
    printf("Error: Could not create routing table from file %s\n", argv[1]);
  }

  /* Sort Routing Table */

  //TODO: Sort Routing Table (Mergesort)

  /* Build Trace Array with Gold Outputs */
  if((trace = create_trace(argv[2], table, &num_tests)) == NULL) {
    printf("Error: Could not create trace from file %s\n", argv[2]);
  }

  /* Test Routing Table implementation */

  // build routing table structure from table
  small_table_t *s_table; 

  // Run test (second argument is function pointer)
  test_routing_table(trace, num_tests, (void*)s_table, lookup_small_table);

  /* Free Resources */
  destroy_routing_table(table);
  destroy_routing_table(trace);

  return EXIT_SUCCESS;
}

uint32_t lookup_small_table(uint32_t dest_ip, void *table) {
  small_table_t *s_table;

  s_table = (small_table_t *)table;

  return 0;
}
