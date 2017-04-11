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
  small_table_t *s_table = NULL;
  if((s_table = build_small_table(table, num_entries)) == NULL) {
    printf("Error: Could not build small table\n");
    return EXIT_FAILURE;
  }

  // Run test (second argument is function pointer)
  printf("Testing small tables\n");
  test_routing_table(trace, num_tests, (void*)s_table, lookup_small_table);

  /* Free Resources */
  destroy_routing_table(table);
  destroy_routing_table(trace);
  destroy_small_table(s_table);

  return EXIT_SUCCESS;
}


small_table_t *build_small_table(route_table_entry_t *table, int table_size) {

  small_table_t *s_table;
  chunk_t *temp;
  int i,j,k;
  uint32_t pointers[table_size];

  if ((s_table = malloc(sizeof(small_table_t))) == NULL) {
    printf("Error: Could not allocate space for small table\n");
    return NULL;
  }

  if ((s_table->next_hop_table = malloc(sizeof(uint32_t) * table_size)) == NULL) {
    printf("Error: Could not allocate space for next hop table\n");
    return NULL;
  }

  // Sort table by mask length
  mergesort(table, table_size, MASK_LEN);

  /* Build L3 Chunks */

  // Sort lengths 25-32 by IP
  i = 0;
  while ((i < table_size) && (table[i].dest_addr.mask > 24)) i++;
  mergesort(table, i, IP_ADDR);

  i = 0;
  while (table[i].dest_addr.mask > 24) {
    j = 1;
    while ((i+j < table_size) && 
    ((table[i].dest_addr.address & L3_MASK) == (table[i+j].dest_addr.address & L3_MASK))) {
      j++;
    }  
    // j now contains the number of entries in this chunk
    printf("Found L3 chunk of size: %d\n", j);

    // L3 will always be pointers into the routing table
    for (k=0; k < j; k++) {
      pointers[k] = table[k+i].next_hop_addr & ~HEAD_PTR_TYPE_MASK;
    }

    if (j <= 8) 
      temp = build_sparse_chunk(&table[i], pointers, j, 3);
    else if (j <= 64) 
      temp = build_dense_chunk(&table[i], pointers, j);
    else 
      temp = build_vdense_chunk(&table[i], pointers, j);

    // update loop
    i = i + j;
  }


  /* Build L2 Chunks */



  /* Build L1 */


  /* Build maptable */


  return NULL;
}


void destroy_small_table(small_table_t *table) {
  // TODO
}

chunk_t *build_sparse_chunk(route_table_entry_t *table, uint32_t *pointers, int size, int level) {
  chunk_t *chunk = NULL;
  int i;

  if((chunk = malloc(sizeof(chunk_t))) == NULL) {
    printf("Error: Couldn't allocate space for sparse chunk\n");
    return NULL; 
  }

  chunk->sparse.type = CHUNK_TYPE_SPARSE;
  chunk->sparse.num_heads = size;

  if(((chunk->sparse.heads = malloc(sizeof(uint8_t) * size)) == NULL) || 
      ((chunk->sparse.pointers = malloc(sizeof(uint32_t) *size)) == NULL)) {
    printf("Error: Couldn't allocate space for arrays in sparse chunk\n");
    return NULL;
  }

  for(i = 0; i < size; i++) {
    if(level == 3) 
      chunk->sparse.heads[i] = (uint8_t)(table[i].dest_addr.address & L3_MASK);
    else 
      chunk->sparse.heads[i] = (uint8_t)((table[i].dest_addr.address & L2_MASK) >> 8);
      
    chunk->sparse.pointers[i] = pointers[i];
  }
 
  return NULL;
}

chunk_t *build_dense_chunk(route_table_entry_t *table, uint32_t *pointers, int size) {
  // TODO
   
  chunk_t *chunk = NULL;

  if((chunk = malloc(sizeof(chunk_t))) == NULL) {
    printf("Error: Couldn't allocate space for dense chunk\n");
    return NULL; 
  }

  return NULL;
}

chunk_t *build_vdense_chunk(route_table_entry_t *table, uint32_t *pointers, int size) {
  // TODO
 
  chunk_t *chunk = NULL;

  if((chunk = malloc(sizeof(chunk_t))) == NULL) {
    printf("Error: Couldn't allocate space for very dense chunk\n");
    return NULL; 
  }

  return NULL;
}

uint32_t lookup_small_table(uint32_t dest_ip, void *table) {
  small_table_t *s_table;

  uint32_t ix, bix, bit, pix, pointer;

  uint16_t codeword, ten, six;

  uint8_t maptable_off;

  s_table = (small_table_t *)table;

  /* Lookup Level 1 */
  
  ix  = (IX_BM  & dest_ip) >> 20;
  bix = (BIX_BM & dest_ip) >> 22;
  bit = (BIT_BM & dest_ip) >> 16;

  codeword = s_table->l1.codewords[ix];
  six = (codeword & CODEWORD_6_BM) >> 10;
  ten = (codeword & CODEWORD_10_BM);

  maptable_off = s_table->maptable[ten][bit >> 1];
  maptable_off = (bit & 0x01) ? maptable_off >> 4 : maptable_off & 0x0f;

  pix = s_table->l1.base[bix] + six + maptable_off;

  pointer = s_table->l1.pointers[pix];

  if (!(pointer & HEAD_PTR_TYPE_MASK))  // if nonzero, pointer to l2
    return s_table->next_hop_table[pointer & HEAD_PTR_PTR_MASK];

  /* Lookup Level 2 */

  pointer = get_chunk_ptr(dest_ip, 2, pointer, s_table);

  if (!(pointer & HEAD_PTR_TYPE_MASK))  // if nonzero, pointer to l3
    return s_table->next_hop_table[pointer & HEAD_PTR_PTR_MASK];
 
  /* Lookup Level 3 */
  
  pointer = get_chunk_ptr(dest_ip, 3, pointer, s_table);

  return s_table->next_hop_table[pointer & HEAD_PTR_PTR_MASK];
}



uint32_t get_chunk_ptr (uint32_t dest_ip, uint32_t level, uint32_t pointer, small_table_t *s_table) {
  
  chunk_t chunk;
  uint8_t addr;
  int i;
  uint32_t out_pointer;

  // for calculating cut
  uint32_t ix, bix, bit, pix;
  uint16_t codeword, ten, six;
  uint8_t maptable_off;

  if (level == 2) {
    chunk = s_table->l2[pointer];
    addr = (dest_ip & 0x0000ff00) >> 8;
  }
  else {
    chunk = s_table->l3[pointer];
    addr = dest_ip & 0x000000ff;
  }

  // Check the type of chunk 

  if        (chunk.sparse.type == CHUNK_TYPE_SPARSE) { // 1-8 heads
    i = chunk.sparse.num_heads/2;
    //TODO: May need ip mask to do this linear search
    if (addr >= chunk.sparse.heads[i]) {
      for(i = i; i < chunk.sparse.num_heads; i++) {
        if(addr >= chunk.sparse.heads[i]) {
          out_pointer = chunk.sparse.pointers[i];
          break;
        }
      }
    } else {
      for(i = 0; i < i; i--) {
        if(addr >= chunk.sparse.heads[i]) {
          out_pointer = chunk.sparse.pointers[i];
          break;
        }
      } 
    }

  } else if (chunk.sparse.type == CHUNK_TYPE_DENSE) { // 9-64 heads
    ix  = (IX_2_3_BM  & addr) >> 4;
    bit = (BIT_2_3_BM & addr);

    codeword = chunk.dense.cut.codewords[ix];
    six = (codeword & CODEWORD_6_BM) >> 10;
    ten = (codeword & CODEWORD_10_BM);

    maptable_off = s_table->maptable[ten][bit >> 1];
    maptable_off = (bit & 0x01) ? maptable_off >> 4 : maptable_off & 0x0f;

    // Only one base index
    pix = chunk.dense.cut.base[0] + six + maptable_off;

    out_pointer = chunk.dense.cut.pointers[pix];

  } else if (chunk.sparse.type == CHUNK_TYPE_VERYDENSE) { // 65-256 heads
    ix  = (IX_2_3_BM  & addr) >> 4;
    bix = (BIX_2_3_BM & addr) >> 6;
    bit = (BIT_2_3_BM & addr);

    codeword = chunk.dense.cut.codewords[ix];
    six = (codeword & CODEWORD_6_BM) >> 10;
    ten = (codeword & CODEWORD_10_BM);

    maptable_off = s_table->maptable[ten][bit >> 1];
    maptable_off = (bit & 0x01) ? maptable_off >> 4 : maptable_off & 0x0f;

    // Only one base index
    pix = chunk.dense.cut.base[bix] + six + maptable_off;

    out_pointer = chunk.dense.cut.pointers[pix];
  }
 
  return out_pointer;
}
