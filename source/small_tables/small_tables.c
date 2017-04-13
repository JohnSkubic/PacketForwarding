/*
 *
 *  Created By: John Skubic 
 *
 *  Description:
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

uint16_t *build_map_table() {
  int i,j,k;
  int last_ptr = 1;
  int ptr = 1;
  uint16_t bmask = 0x0001;
  uint16_t *ping, *pong, *temp;

  ping = malloc(sizeof(uint16_t) * 678);
  pong = malloc(sizeof(uint16_t) * 678);

  ping[0] = 1; 
 
  for(i = 2; i <= 16; i*=2) {
    ptr = 0;
    for(j=0; j < last_ptr; j++) {
      for(k=0; k < last_ptr; k++) {
        pong[ptr++] = (ping[j] & bmask) | ((ping[k] & bmask) << (i/2));
      }
    }
    pong[ptr++] = 1 << (i-1);
    last_ptr = ptr;
    bmask = bmask | (bmask << i/2);
    temp = ping;
    ping = pong;
    pong = temp;
  }
  free(pong);
  return ping;
}

small_table_t *build_small_table(route_table_entry_t *table, int table_size) {

  small_table_t *s_table;
  int i,j,k;
  node_t *tree = NULL;
  node_t *temp = NULL;
  node_t *curr = NULL;
  uint32_t mask, addr, bit;

  if ((s_table = malloc(sizeof(small_table_t))) == NULL) {
    printf("Error: Could not allocate space for small table\n");
    return NULL;
  }

  if ((s_table->next_hop_table = malloc(sizeof(uint32_t) * table_size)) == NULL) {
    printf("Error: Could not allocate space for next hop table\n");
    return NULL;
  }


  /*
 *
 *  Build Maptable
 *
 */

  uint16_t *maptable; // length = 676
  maptable = build_map_table();

  // Sort table by mask length
  mergesort(table, table_size, MASK_LEN);

  /* Build Binary Tree Representation */
  tree = new_node();
  tree->type = HEAD_TREE_ROOT;

  // Add rules as nodes
  for(i = 0; i < table_size; i++) {
    mask = table[i].dest_addr.mask;
    addr = table[i].dest_addr.address;
    curr = tree;
    for (k = 0; k < mask; k++) { // move down tree
      bit = (addr & (0x80000000 >> k)) ? 1 : 0;
      if (bit) { // look right
        if(curr->r == NULL) {
          temp = new_node();
          temp->type = HEAD_ROOT;
          curr->r = temp;
        }     
        curr = curr->r;
      } else { // look left
        if(curr->l == NULL) {
          temp = new_node();
          temp->type = HEAD_ROOT;
          curr->l = temp;
        }
        curr = curr->l;
      }
    } 
    // curr is the genuine head
    curr->type = HEAD_GENUINE;
    curr->addr = addr;
    curr->nhop = table[i].next_hop_addr;
  }

  // Complete Tree (all nodes have 0 or 2 leaves)
  complete_tree(tree, tree);

  /* 
  *
  * Build L1 
  *
  */

  // build codewords and bases

  s_table->l1.codewords = malloc(sizeof(uint16_t) * L1_N_CODEWORDS);
  s_table->l1.base = malloc(sizeof(uint16_t) * L1_N_BASES);
  memset(s_table->l1.codewords, 0, sizeof(uint16_t) * L1_N_CODEWORDS);
  memset(s_table->l1.base, 0, sizeof(uint16_t) * L1_N_BASES);

  uint16_t *codewords = malloc(sizeof(uint16_t) * L1_N_CODEWORDS); // actual codewords
  memset(codewords, 0, sizeof(uint16_t) * L1_N_CODEWORDS);

  build_L1(tree, codewords, 0);

  return NULL;
}

void build_L1(node_t *node, uint16_t *codewords, int level) {
  int codeword_num;
  int base_num;
  int i;
  uint16_t temp;

  if (level == 15) { // L1 stops at cut 16
    if (node->type == HEAD_GENUINE) {
      codeword_num = (node->addr >> 20);
      codewords[codeword_num] |= 0x8000 >> ((node->addr & BIT_BM) >> 16);
    } else if (node->type == HEAD_ROOT) {
      codeword_num = (node->addr >> 20);
      codewords[codeword_num] |= 0x8000 >> ((node->addr & BIT_BM) >> 16);
    }
  } else if (node->type == HEAD_GENUINE) { // Fill in entry for members
    codeword_num = (node->addr >> 20);
    codewords[codeword_num] |= 0x8000 >> ((node->addr & BIT_BM) >> 16);
  }
  else { // continue recursion
    build_L1(node->l, codewords, level+1);
    build_L1(node->r, codewords, level+1);
  }
}

inline uint16_t get_codeword_off(uint16_t codeword) {
  return (codeword & CODEWORD_6_BM);
}

inline uint16_t get_codeword_idx(uint16_t codeword) {
  return ((codeword & CODEWORD_10_BM) >> 6);
}

inline uint16_t set_codeword_off(uint16_t codeword, uint16_t off) {
  return ((codeword & ~CODEWORD_6_BM) | (off & CODEWORD_6_BM));
}

inline uint16_t set_codeword_idx(uint16_t codeword, uint16_t idx) {
  return ((codeword & ~CODEWORD_10_BM) | ((idx << 6) & CODEWORD_10_BM));
}

void complete_tree(node_t *node, node_t *ancestor) {
  if (node->type == HEAD_GENUINE) {
    ancestor = node;

    if(((node->r != NULL) && (node->r == HEAD_GENUINE)) &&
    ((node->l != NULL) && (node->l == HEAD_GENUINE))) {
      node->type = HEAD_ROOT;
    }
  }

  if ((node->l == NULL) ^ (node->r == NULL)) { // not complete
    if (node->type == HEAD_GENUINE) 
      node->type = HEAD_ROOT;
    if (node->l == NULL) {
      node->l = new_node();
      node->l->type = HEAD_GENUINE;
      node->l->addr = ancestor->addr;
      node->l->nhop = ancestor->nhop;
      complete_tree(node->r, ancestor);
    } else { // node->r
      node->r = new_node();
      node->r->type = HEAD_GENUINE;
      node->r->addr = ancestor->addr;
      node->r->nhop = ancestor->nhop;
      complete_tree(node->l, ancestor);
    } 
  } else {
    if (node->r != NULL)
      complete_tree(node->r, ancestor);
    if (node->l != NULL)
      complete_tree(node->l, ancestor);
  }
}


node_t *new_node() {
  node_t *node = NULL;

  node = malloc(sizeof(node_t));

  node->type = HEAD_UNDEF;
  node->addr = 0;
  node->nhop = 0;
  node->l = NULL;
  node->r = NULL;
  
  return node;
}

void destroy_small_table(small_table_t *table) {
  // TODO
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

  pointer = s_table->l1_ptr_table[pix];

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
   return 0;
}
