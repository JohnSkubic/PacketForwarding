/*
 *
 *  Created By: John Skubic 
 *
 *  Description:
 *
 */

#ifndef UTILITY_H
#define UTILITY_H

#ifndef uint32_t
#define uint32_t unsigned int
#endif

#ifndef uint8_t
#define uint8_t unsigned char
#endif

#define MASK_LEN 0
#define IP_ADDR 1

//ex: 192.256.0.0/16
//address <- 192.256.0.0
//mask    <- 16
typedef struct ip_t {
  uint32_t address;
  int mask;
} ip_t;

typedef struct route_table_entry_t {
  ip_t dest_addr;
  uint32_t next_hop_addr;
} route_table_entry_t;

//building routing table from filter file
route_table_entry_t *create_routing_table (char *filename, int *size);
//build an array of test cases from the trace file
route_table_entry_t *create_trace (char *filename, route_table_entry_t *table, int *num_tests);
void destroy_routing_table(route_table_entry_t *table);

void test_routing_table(route_table_entry_t *trace, int num_tests, void *table, uint32_t (*lookup)(uint32_t, void*));

uint32_t get_gold_nexthop(uint32_t ip, route_table_entry_t *table);

void mergesort(route_table_entry_t *table, int size);

void mergesort_rec(route_table_entry_t *table, route_table_entry_t *sorted, int l_idx, int u_idx);

#endif // UTILITY_H
