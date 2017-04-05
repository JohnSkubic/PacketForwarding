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
  int num_tests, num_entries;
  int i = 0;
  
  if (argc < 3) {
    printf("Usage: %s <filter_file> <trace_file>\n", argv[0]);
    return EXIT_FAILURE;
  }


  /* Build Routing Table */

  printf("Building the routing table\n");
  if((table = create_routing_table(argv[1], &num_entries)) == NULL) {
    printf("Error: Could not create routing table from file %s\n", argv[1]);
  }

  printf("Found %d unique IP entries\n", num_entries);

  /* Sort Routing Table */

  //Sort Routing Table (Mergesort)
  printf("Building gold model\n");
  mergesort(table, num_entries, MASK_LEN);
  printf("Gold model sanity check: ");
  for (i=0; i < num_entries-1; i++) {
    if (table[i].dest_addr.mask < table[i+1].dest_addr.mask) {
      printf("Error at idx: %d\n", i);
      return EXIT_FAILURE;
    } 
  }
  printf("PASSED\n");

  /* Build Trace Array with Gold Outputs */
  printf("Generating expected outputs\n");
  if((trace = create_trace(argv[2], table, num_entries, &num_tests)) == NULL) {
    printf("Error: Could not create trace from file %s\n", argv[2]);
  }

  /* Test Routing Table implementation */

  // build routing table structure from table
  small_table_t *s_table; 

  // Run test (second argument is function pointer)
  printf("Testing small tables\n");
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
