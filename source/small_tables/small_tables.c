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
  * Fill in next hop table
  */

  for(i = 0; i < table_size; i++) {
    s_table->next_hop_table[i] = table[i].next_hop_addr;
    //printf("ADDR: %x NHOP: %d\n", table[i].dest_addr.address, table[i].next_hop_addr);
  }
  s_table->num_entries = table_size;


  /*
  *
  *  Build Maptable
  *
  */

  uint16_t *maptable; // length = 676
  maptable = build_map_table();


  /*  
  *
  * Build Binary Tree Representation
  *
  */

  // Sort table by mask length
  mergesort(table, table_size, MASK_LEN);

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
  complete_tree(tree, tree, 0, 0x00000000);

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

  lnode_t *ptrs = malloc(sizeof(lnode_t) * L1_N_CODEWORDS); //ptrs for codewords
  memset(ptrs, 0, sizeof(lnode_t) * L1_N_CODEWORDS);

  build_L1_codewords(tree, codewords, ptrs, 0);

  //for(i = 0; i < L1_N_CODEWORDS; i++) {
  //  if(codewords[i] != 0)
  //    printf("IDX: %d CODEWORD: %x\n", i, codewords[i]);
  //}

  set_L1_codeword_base(codewords, ptrs, maptable, s_table);

  for(i =0; i < L1_N_CODEWORDS; i++) {
    if((s_table->l1.codewords[i] & CODEWORD_10_BM) < 676)
      printf("CODE_OFF: %d BASE_OFF: %d i: %d\n", (s_table->l1.codewords[i] & CODEWORD_6_BM) >> 10, s_table->l1.base[i/4], i);
  }

  return NULL;
}


void set_L1_codeword_base(uint16_t *codewords, lnode_t *ptrs, uint16_t *maptable, small_table_t *s_table) {
  int i,j,k;
  int ptr_cnt = 0;
  int l2_ptr_cnt = 0;
  uint32_t next_hop = 0;
  lnode_t *last_ptr = NULL;
  lnode_t *temp = NULL;
  uint16_t nhop_idx;
  uint16_t nhop_ptr;
  uint16_t mask;
  int ptrs_in_bvects = 0;
  uint16_t ten,six;


  // Determine size of L1 PTR TABLE and allocate space
  ptr_cnt = 0;
  for (i=0; i < L1_N_CODEWORDS;i++) {
    if(!((codewords[i] == 0) || (codewords[i] == 0x8000))) {
      for (j = 0; j < 16; j++) {
        if (codewords[i] & mask) {
          ptr_cnt++; 
        }
        mask = mask >> 1;
      }
    }
  }

  s_table->l1_ptr_table = malloc(sizeof(uint16_t) * ptr_cnt);


  ptr_cnt = 0;
  for (i = 0; i < L1_N_CODEWORDS; i++) {
    // set 10 bit based on codeword
    if(i%4 == 0) {
      s_table->l1.base[i/4] = ptr_cnt;
      ptrs_in_bvects = 0;
    }

    if((codewords[i] == 0) || (codewords[i] == 0x8000)) {// bit masks 0 & 1 have ptr directly encoded
      // ten = upper 10bits + 676; six = lower six bits
      temp = get_node_by_idx(&ptrs[i], 0); //0x8000 
      if(temp != NULL)
        last_ptr = temp;

      nhop_idx = get_nhop_idx(s_table->next_hop_table, last_ptr->nhop, s_table->num_entries);
      //set the codeword
      s_table->l1.codewords[i] = 0;
      s_table->l1.codewords[i] |= (nhop_idx & MASK_6) << 10;
      s_table->l1.codewords[i] |= (((nhop_idx & MASK_10_MSB) >> 6) + 676);
      //printf("For idx: %x Build Codeword: %x\n", nhop_idx, s_table->l1.codewords[i]);
    } else {
      // iterate through each active head (start with MSB)
      
      // Build 6bit and 10bit codeword

      ten = get_maptable_idx(codewords[i], maptable);
      six = ptrs_in_bvects;
      printf("Setting codeword[%d] six: %d ten: %d\n", i, six, ten);
      s_table->l1.codewords[i] = 0;
      s_table->l1.codewords[i] |= (six << 10);
      s_table->l1.codewords[i] |= ten & CODEWORD_10_BM; 

      mask = 0x8000;
      for (j = 0; j < 16; j++) {
        if (codewords[i] & mask) {
          temp = get_node_by_idx(&ptrs[i], j);
          last_ptr = temp;
          if(temp->type != PTR_TYPE_NH) { // ptr to L2 Chunk
            //TODO: L2 - figure out type here
            s_table->l1_ptr_table[ptr_cnt] = l2_ptr_cnt | (PTR_TYPE_SPARSE << 14); 
            l2_ptr_cnt++;
          }
          else { // add index in nh table to L1 table
            s_table->l1_ptr_table[ptr_cnt] = get_nhop_idx(s_table->next_hop_table, last_ptr->nhop, s_table->num_entries) & ~HEAD_PTR_TYPE_MASK;
          }
          ptrs_in_bvects++;
          ptr_cnt++;
        }
        mask = mask >> 1;
      }
    }
  }
}

uint16_t get_maptable_idx(uint16_t bitvect, uint16_t *maptable) {
  int i;
  uint16_t idx = -1;
  for(i = 0; i < 676; i++) {
    if (maptable[i] == bitvect) {
      idx = i;
      break;
    }
  }
  if(idx == -1) {
    printf("ERROR: Couldn't find %x in maptable\n", bitvect);
  }
  return idx;
}

uint16_t get_nhop_idx(uint32_t *nhop_table, uint32_t nhop, int size) {
  int i;
  uint32_t idx = -1;
  for(i = 0; i < size; i++) {
    if (nhop_table[i] == nhop) {
      idx = i;
      break;
    }
  }
  if(idx == -1) {
    printf("ERROR: Couldn't find %d in nexthoptable\n", nhop);
  }
  return idx;
}


lnode_t *get_node_by_idx(lnode_t *head, uint8_t idx) {
  lnode_t *temp = head;

  if (temp->next == NULL) return NULL;
  else temp = temp->next;

  while(temp != NULL) {
    if(temp->idx == idx) return temp;
    temp = temp->next;
  }
  return NULL;
}

void add_node(lnode_t *head, uint8_t idx, uint8_t type, uint32_t nhop) {
  lnode_t *temp = head;

  while(temp->next != NULL) {
    temp = temp->next;
    //newer node data is always better (lower down the tree)
    if (temp->idx == idx) {
      temp->type = type;
      temp->nhop = nhop;
      return;
    }
  }

  temp->next = malloc(sizeof(lnode_t));
  temp->next->idx = idx;
  temp->next->type = type;
  temp->next->nhop = nhop;
  temp->next->next = NULL;
}

void build_L1_codewords(node_t *node, uint16_t *codewords, lnode_t *ptrs, int level) {
  int codeword_num;
  int base_num;
  int i;
  uint16_t temp;

  if (level == 16) { // L1 stops at cut 16
    codeword_num = (node->addr >> 20);
    codewords[codeword_num] |= 0x8000 >> ((node->addr & BIT_BM) >> 16);
    if (node->type == HEAD_GENUINE) {
      //printf("HG ADDR: %x BIT: %x SHIFT: %x NH: %x\n",node->addr, node->addr & BIT_BM, (node->addr & BIT_BM) >> 16, node->nhop);
      add_node(&ptrs[codeword_num], (node->addr & BIT_BM)>>16, PTR_TYPE_NH, node->nhop);
    } else if (node->type == HEAD_ROOT) {
      //printf("ADDR: %x BIT: %x SHIFT: %x\n",node->addr, node->addr & BIT_BM, (node->addr & BIT_BM) >> 16);
      add_node(&ptrs[codeword_num], (node->addr & BIT_BM)>>16, PTR_TYPE_SPARSE, node->nhop); //TODO: Figure out actual L2 type
    }
  } else if (node->type == HEAD_GENUINE) { // Fill in entry for members
    //printf("NLC ADDR: %x BIT: %x SHIFT: %x level: %d\n",node->addr, node->addr & BIT_BM, (node->addr & BIT_BM) >> 16, level);
    codeword_num = (node->addr >> 20);
    codewords[codeword_num] |= 0x8000 >> ((node->addr & BIT_BM) >> 16);
    add_node(&ptrs[codeword_num], (node->addr & BIT_BM)>>16, PTR_TYPE_NH, node->nhop);
  }
  else { // continue recursion
    build_L1_codewords(node->l, codewords, ptrs, level+1);
    build_L1_codewords(node->r, codewords, ptrs, level+1);
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

void complete_tree(node_t *node, node_t *ancestor, int depth, uint32_t addr) {
  if (node->type == HEAD_GENUINE) {
    ancestor = node;

    if(((node->r != NULL) && (node->r->type == HEAD_GENUINE)) &&
    ((node->l != NULL) && (node->l->type == HEAD_GENUINE))) {
      node->type = HEAD_ROOT;
    }
  }

  if ((node->l == NULL) ^ (node->r == NULL)) { // not complete
    if (node->type == HEAD_GENUINE) 
      node->type = HEAD_ROOT;
    if (node->l == NULL) {
      node->l = new_node();
      node->l->type = HEAD_GENUINE;
      node->l->addr = addr;
      node->l->nhop = ancestor->nhop;
      complete_tree(node->r, ancestor, depth+1, addr | (0x80000000 >> depth));
    } else { // node->r
      node->r = new_node();
      node->r->type = HEAD_GENUINE;
      node->r->addr = addr;
      node->r->nhop = ancestor->nhop;
      complete_tree(node->l, ancestor, depth+1, addr);
    } 
  } else {
    if (node->r != NULL)
      complete_tree(node->r, ancestor, depth+1, addr | (0x80000000 >> depth));
    if (node->l != NULL)
      complete_tree(node->l, ancestor, depth+1, addr);
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
