/*
 *
 *  Created By: John Skubic 
 *
 *  Description:
 *
 */

#include "utility.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define FILTER_FORMAT "@%*u.%*u.%*u.%*u/%*u %u.%u.%u.%u/%u"
#define TRACE_FORMAT "%*d %d %*d %*d %*d %*d"

//parses the output of db_generator
route_table_entry_t *create_routing_table (char *filename, int *size) {
  route_table_entry_t *table = NULL;
  FILE *fptr;
  uint32_t ip3, ip2, ip1, ip0;
  int mask;
  char line[256];
  int count = 0;
  int num_lines = 0;  
  

  if((fptr = fopen(filename, "r")) == NULL) {
    printf("Error: Failed to open file %s for reading\n", filename);
    return NULL;
  }

  while (fgets(line, sizeof line, fptr)) 
    num_lines++;

  *size = num_lines;
  fseek(fptr, 0, SEEK_SET);
 
  if ((table = (route_table_entry_t*)malloc(sizeof(route_table_entry_t) * num_lines)) == NULL) {
    printf("Error: Couldn't allocate space for routing table\n");
    fclose(fptr);
    return NULL;
  }
 
  while (fgets(line, sizeof line, fptr)) {
    sscanf(line, FILTER_FORMAT, &ip3, &ip2, &ip1, &ip0, &mask);
    ip0 = ip0 & 0x000000ff;
    ip0 = ip0 | ((ip1 & 0x000000ff) << 8);
    ip0 = ip0 | ((ip2 & 0x000000ff) << 16);
    ip0 = ip0 | ((ip3 & 0x000000ff) << 24);
    table[count].dest_addr.address = ip0;
    table[count].dest_addr.mask = mask;
    table[count].next_hop_addr = count;
    count++;
  }

  fclose(fptr);

  return table;
}

//parses the output of trace_generator
//table must be sorted first by ip and then by length by a stable sorting algorithm
route_table_entry_t *create_trace (char *filename, route_table_entry_t *table, int *num_tests) {
  route_table_entry_t *trace = NULL;
  FILE *fptr;
  char line[256];
  int count = 0;
  int num_lines = 0;  
  uint32_t ip; 

  if((fptr = fopen(filename, "r")) == NULL) {
    printf("Error: Failed to open file %s for reading\n", filename);
    return NULL;
  }

  while (fgets(line, sizeof line, fptr)) 
    num_lines++;

  fseek(fptr, 0, SEEK_SET);
  *num_tests = num_lines;
 
  if ((trace = (route_table_entry_t*)malloc(sizeof(route_table_entry_t) * num_lines)) == NULL) {
    printf("Error: Couldn't allocate space for routing table\n");
    fclose(fptr);
    return NULL;
  }
 
  while (fgets(line, sizeof line, fptr)) {
    sscanf(line, TRACE_FORMAT, &ip);
    trace[count].dest_addr.address = ip;
    trace[count].dest_addr.mask = 0;
    trace[count].next_hop_addr = get_gold_nexthop(ip, table);
    count++;
  }

  fclose(fptr);

  return trace;
}

void destroy_routing_table(route_table_entry_t *table) {
  if (table != NULL)
    free(table);
}

void test_routing_table(route_table_entry_t *trace, int num_tests, void *table, uint32_t (*lookup)(uint32_t, void*)) {
  int num_incorrect;
  int i;
  uint32_t next_hop;
  clock_t start, end;
  double cpu_time_used;

  num_incorrect = 0;

  for(i = 0; i < num_tests; i++) {
    next_hop = lookup(trace[i].dest_addr.address, table);
    if(trace[i].next_hop_addr != next_hop) {
      printf("Incorrect lookup for index: %d.  Expected next hop: %d  Got next hop: %d\n", i, trace[i].next_hop_addr, next_hop);
      num_incorrect++;
    }
  }

  if (num_incorrect == 0) {
    start = clock();
    
    for(i = 0; i < num_tests; i++) {
      next_hop = lookup(trace[i].dest_addr.address, table);
    }

    end = clock();
    cpu_time_used = ((double)(end - start)) / CLOCKS_PER_SEC;
    printf("Time Elapsed: %f Number of Lookups: %d\n", cpu_time_used, num_tests);
  }

}

uint32_t get_gold_nexthop(uint32_t ip, route_table_entry_t *table) {
  return 0;
}


void mergesort(route_table_entry_t *table, int size) {

  route_table_entry_t *copy;
  int i;

  copy = (route_table_entry_t*)malloc(sizeof(route_table_entry_t)*size);
  for (i=0; i < size; i++) {
    copy[i] = table[i];
  }
  mergesort_rec(copy, table, 0, size-1);
  free(copy);

}

void mergesort_rec(route_table_entry_t *table, route_table_entry_t *sorted, int l_idx, int u_idx) {
  int mid;
  int idx, l_1, u_1, l_2, u_2;

  mid = (u_idx + l_idx) / 2;

  if ((u_idx - l_idx) > 1) {
    l_1 = l_idx;
    u_1 = mid;
    l_2 = mid+1;
    u_2 = u_idx;
    mergesort_rec(sorted, table, l_1, u_1);
    mergesort_rec(sorted, table, l_2, u_2);  
    u_1++;
    u_2++; 
    
    while ((l_1 != u_1) || (l_2 != u_2)) {
      if (l_2 == u_2) { // done with arr2
        sorted[idx++].dest_addr.mask = table[l_1++].dest_addr.mask;
      } else if (l_1 == u_1) { // done with arr 1
        sorted[idx++].dest_addr.mask = table[l_2++].dest_addr.mask;
      } else if (sorted[l_1].dest_addr.mask >= table[l_2].dest_addr.mask) { // pick from arr 1
        sorted[idx++].dest_addr.mask = table[l_1++].dest_addr.mask;
      } else { // pick from arr 2
        sorted[idx++].dest_addr.mask = table[l_2++].dest_addr.mask;
      }
    }
  }
}


