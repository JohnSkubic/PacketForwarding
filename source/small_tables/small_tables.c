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

void print_tree(node_t *node, int depth) {
  if (node->r != NULL) {
    print_tree(node->r, depth+1);
  }
  if (node->l != NULL) {
    print_tree(node->l, depth+1);
  }

  printf("DEPTH: %d Addr: %x Type: %d Nhop: %d\n", depth, node->addr, node->type, node->nhop);
}

int l1_found;
int l2_found;
int l3_found;


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

  //printf("Building the routing table\n");
  if((table = create_routing_table(argv[1], &num_entries)) == NULL) {
    printf("Error: Could not create routing table from file %s\n", argv[1]);
  }

  printf("Found %d unique IP entries\n", num_entries);

  /* Sort Routing Table */

  //Sort Routing Table (Mergesort)
  //printf("Building gold model\n");
  mergesort(table, num_entries, MASK_LEN);
  //printf("Gold model sanity check: ");
  for (i=0; i < num_entries-1; i++) {
    if (table[i].dest_addr.mask < table[i+1].dest_addr.mask) {
      printf("Error at idx: %d\n", i);
      return EXIT_FAILURE;
    } 
  }
  //printf("PASSED\n");

  /* Build Trace Array with Gold Outputs */
  //printf("Generating expected outputs\n");
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

  //printf("INFO:\nL1_PTRS: %d\nL2_PTRS: %d\nL3_PTRS:%d\n", s_table->n_l1_ptrs, s_table->n_l2_ptrs, s_table->n_l3_ptrs);

  // Run test (second argument is function pointer)
  //printf("Testing small tables\n");
  l1_found = 0;
  l2_found = 0;
  l3_found = 0;
  test_routing_table(trace, num_tests, (void*)s_table, lookup_small_table);

  printf("Percent lookups found in L1: %.2f\n", (((float)l1_found / (float)(l1_found + l2_found + l3_found)) * 100.0));
  printf("Percent lookups found in L2: %.2f\n", (((float)l2_found / (float)(l1_found + l2_found + l3_found)) * 100.0));
  printf("Percent lookups found in L3: %.2f\n", (((float)l3_found / (float)(l1_found + l2_found + l3_found)) * 100.0));

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

// returns the size of the small table in bytes
// This function only counts memory used at lookup
// Variables used to build the table are omitted
int calc_s_table_size(small_table_t *s_table) {
  int size; 
  int i;
  uint16_t ptr;
  uint8_t type;

  // maptable, always same size
  size = 676*8*sizeof(uint8_t);

  // next hop table
  size += s_table->num_entries * sizeof(uint32_t);

  // ptr tables
  size += s_table->n_l1_ptrs * sizeof(uint16_t);
  size += s_table->n_l2_ptrs * sizeof(uint16_t);
  size += s_table->n_l3_ptrs * sizeof(uint16_t);

  // ptrs in the table
  size += sizeof(cut_t); // l1
  size += 2 * sizeof(chunk_t *);
  size += 3 * sizeof(uint16_t *);


  // l1 codewords
  size += L1_N_CODEWORDS * sizeof(uint16_t);
  // l1 bases
  size += L1_N_BASES * sizeof(uint16_t);

  // Iterate through L1 Ptrs to find types of chunks
  for(i=0; i < s_table->n_l1_ptrs; i++) {
    ptr = s_table->l1_ptr_table[i];
    type = ptr >> 14;
    if (type == PTR_TYPE_SPARSE)
      size +=  8 * (sizeof(uint8_t) + sizeof(uint16_t));
    else if (type == PTR_TYPE_DENSE) 
      size += sizeof(uint16_t) + (16 * sizeof(uint16_t));
    else if (type == PTR_TYPE_VERYDENSE)  
      size += (4 * sizeof(uint16_t)) + (16 * sizeof(uint16_t));
  }

  // L2
  for(i=0; i < s_table->n_l2_ptrs; i++) {
    ptr = s_table->l2_ptr_table[i];
    type = ptr >> 14;
    if (type == PTR_TYPE_SPARSE)
      size +=  8 * (sizeof(uint8_t) + sizeof(uint16_t));
    else if (type == PTR_TYPE_DENSE) 
      size += sizeof(uint16_t) + (16 * sizeof(uint16_t));
    else if (type == PTR_TYPE_VERYDENSE)  
      size += (4 * sizeof(uint16_t)) + (16 * sizeof(uint16_t));
  }

  // L3
  for(i=0; i < s_table->n_l3_ptrs; i++) {
    ptr = s_table->l3_ptr_table[i];
    type = ptr >> 14;
    if (type == PTR_TYPE_SPARSE)
      size +=  8 * (sizeof(uint8_t) + sizeof(uint16_t));
    else if (type == PTR_TYPE_DENSE) 
      size += sizeof(uint16_t) + (16 * sizeof(uint16_t));
    else if (type == PTR_TYPE_VERYDENSE)  
      size += (4 * sizeof(uint16_t)) + (16 * sizeof(uint16_t));
  }
  
  return size;
 }

small_table_t *build_small_table(route_table_entry_t *table, int table_size) {

  small_table_t *s_table;
  int i,k;
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
    //printf("Addr: %x Nhop: %d Mask: %d\n", table[i].dest_addr.address, table[i].next_hop_addr, table[i].dest_addr.mask);
    s_table->next_hop_table[i] = table[i].next_hop_addr;
  }
  s_table->num_entries = table_size;


  /*
  *
  *  Build Maptable
  *
  */

  uint16_t *maptable; // length = 676
  maptable = build_map_table();
  build_s_table_map_table(s_table, maptable);

  /*  
  *
  * Build Binary Tree Representation
  *
  */

  // Sort table by mask length
  mergesort(table, table_size, MASK_LEN);

  tree = new_node();
  tree->type = HEAD_TREE_ROOT;
  
  uint32_t tree_addr;
  // Add rules as nodes
  for(i = 0; i < table_size; i++) {
    mask = table[i].dest_addr.mask;
    addr = table[i].dest_addr.address;
    curr = tree;
    tree_addr = 0;
    for (k = 0; k < mask; k++) { // move down tree
      bit = (addr & (0x80000000 >> k)) ? 1 : 0;
      if (bit) { // look right  
        tree_addr |= (0x80000000 >> k);
        if(curr->r == NULL) {
          temp = new_node();
          temp->type = HEAD_ROOT;
          temp->addr = tree_addr;
          curr->r = temp;
        }     
        curr = curr->r;
      } else { // look left
        if(curr->l == NULL) {
          temp = new_node();
          temp->type = HEAD_ROOT;
          temp->addr = tree_addr;
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

  //print_tree(tree, 0);

  /*
  *
  * Build L3
  *
  */

  //printf("\nBUILDING LEVEL 3\n\n");

  int num_ptrs, num_chunks;
  int count;
  uint8_t *types_l2;
  uint8_t *types_l3; 
  uint16_t last_ptr;

  num_ptrs = 0;
  num_chunks = 0;
  last_ptr = 0;
  find_level_sizes(tree, 0, 24, 32, &num_chunks, &num_ptrs);
  
  s_table->n_l3_ptrs = 0;//start at 0 and add as the struct is built num_ptrs;
  s_table->n_l3_chunks = num_chunks; //start at 0 and add as struct built
  types_l3 = malloc(sizeof(uint8_t) *num_chunks);

  s_table->l3 = malloc(sizeof(chunk_t) * num_chunks);
  s_table->l3_ptr_table = malloc(sizeof(uint16_t) * num_ptrs);

  count = 0;
  build_chunk_trees_rec(s_table, tree, maptable, 24, 32, 0, 0, NULL, types_l3, &count, &last_ptr); // builds the tree starting at the give cut
  

  // free l3 memory

  /*
  *
  * Build L2
  *
  */

  //printf("\nBUILDING LEVEL 2\n\n");

  num_ptrs = 0;
  num_chunks = 0;
  last_ptr = 0;
  
  find_level_sizes(tree, 0, 16, 24, &num_chunks, &num_ptrs);

  s_table->n_l2_ptrs = 0;
  s_table->n_l2_chunks = num_chunks;
  types_l2 = malloc(sizeof(uint8_t) * num_chunks);

  s_table->l2 = malloc(sizeof(chunk_t) * num_chunks);
  s_table->l2_ptr_table = malloc(sizeof(uint16_t) * num_ptrs);  

  count = 0;
  build_chunk_trees_rec(s_table, tree, maptable, 16, 24, 0, 0, types_l3, types_l2, &count, &last_ptr);

  /* 
  *
  * Build L1 
  *
  */
  
  //printf("\nBUILDING LEVEL 1\n\n");

  num_ptrs = 0;
  num_chunks = 0;
  last_ptr = 0;
  count = 0;

  find_level_sizes(tree, 0, 0, 16, &num_chunks, &num_ptrs);
  s_table->l1_ptr_table = malloc(sizeof(uint16_t) * num_ptrs); 
 
  s_table->n_l1_ptrs = 0;

  // build codewords and bases

  s_table->l1.codewords = malloc(sizeof(uint16_t) * L1_N_CODEWORDS);
  s_table->l1.base = malloc(sizeof(uint16_t) * L1_N_BASES);
  memset(s_table->l1.codewords, 0, sizeof(uint16_t) * L1_N_CODEWORDS);
  memset(s_table->l1.base, 0, sizeof(uint16_t) * L1_N_BASES);

  uint16_t *codewords = malloc(sizeof(uint16_t) * L1_N_CODEWORDS); // actual codewords
  memset(codewords, 0, sizeof(uint16_t) * L1_N_CODEWORDS);

  lnode_t *ptrs = malloc(sizeof(lnode_t) * L1_N_CODEWORDS); //ptrs for codewords
  memset(ptrs, 0, sizeof(lnode_t) * L1_N_CODEWORDS);

  rec_set_codewords(s_table, codewords, tree, maptable, 16, 0, ptrs);

  //for(i=0; i < L1_N_CODEWORDS;i++) {
  //  if(codewords[i] != 0x8000 && codewords[i] != 0)
  //    printf("CODE: %d WORD: %x\n", i, codewords[i]);
  //}

  set_codewords_ptrs(s_table, &(s_table->l1), codewords, ptrs, maptable, 4, 0, types_l2, &count, &last_ptr); 

  // free used memory
  free(codewords);
  free(maptable);
  for (i = 0; i < L1_N_CODEWORDS; i++) {
    destroy_node(ptrs[i].next); 
  }
  free(ptrs);

  printf("Size of Small Table : %d bytes\n", calc_s_table_size(s_table));

  return s_table;
}

// num_chunks - the number of chunks starting at level minlevel
// num_ptrs - the number of pointers required between levels minlevel and maxlevel
void find_level_sizes(node_t *tree, int clevel, int minlevel, int maxlevel, int *num_chunks, int *num_ptrs) {  
  if((tree->type == HEAD_GENUINE) && (clevel > minlevel)) {
    *num_ptrs = *num_ptrs + 1;
  }
  
  if (clevel < maxlevel) {
    if (tree->l != NULL) 
      find_level_sizes(tree->l, clevel+1, minlevel, maxlevel, num_chunks, num_ptrs);
    if (tree->r != NULL)
      find_level_sizes(tree->r, clevel+1, minlevel, maxlevel, num_chunks, num_ptrs);
  } 
  else if (clevel == maxlevel) {
    if (tree->type == HEAD_ROOT) { 
      *num_ptrs = *num_ptrs + 1;
    }
  }
  
  if ((clevel == minlevel) && (tree->type == HEAD_ROOT))
      *num_chunks = *num_chunks + 1;
}

int build_chunk_trees_rec(small_table_t *s_table, node_t *head, uint16_t *maptable, int cut, int max_depth, int chunk_num, int clevel, uint8_t *i_types, uint8_t *o_types, int *gcount, uint16_t *last_ptr) {
  if (clevel < cut) {
    if (head->l != NULL)
      chunk_num = build_chunk_trees_rec(s_table, head->l, maptable, cut, max_depth, chunk_num, clevel+1, i_types, o_types, gcount, last_ptr);
    if (head->r != NULL)
      chunk_num = build_chunk_trees_rec(s_table, head->r, maptable, cut, max_depth, chunk_num, clevel+1, i_types, o_types, gcount, last_ptr);
  }
  else if ((clevel == cut) && (head->type == HEAD_ROOT)){
    build_chunk_trees(s_table, head, maptable, cut, max_depth, chunk_num, i_types, o_types, gcount, last_ptr);
    chunk_num++;
  }
  return chunk_num;
}

void build_chunk_trees(small_table_t *s_table, node_t *head, uint16_t *maptable, int cut, int max_depth, int chunk_num, uint8_t *i_types, uint8_t *o_types, int *gcount, uint16_t *last_ptr) {
  //printf("Building chunk number: %d\n", chunk_num); 
  int num_ptrs = 0;
  int num_chunks = 0;

  chunk_t *chunk_arr = NULL;

  //choose the correct level
  if (cut == 16) {
    chunk_arr = s_table->l2;
  }
  else if (cut == 24) {
    chunk_arr = s_table->l3;
  }
  
  find_level_sizes(head, cut, cut, max_depth, &num_chunks, &num_ptrs);

  //printf("cut: %d max %d CHUNKS %d PTRS %d\n", cut, max_depth, num_chunks, num_ptrs);

  if (num_ptrs <= 8) { //SPARSE
    chunk_arr[chunk_num] = build_sparse_chunk(s_table, head, cut, max_depth, i_types, gcount, last_ptr);
    o_types[chunk_num] = PTR_TYPE_SPARSE; 
  } else if (num_ptrs <= 64) { //DENSE
    chunk_arr[chunk_num] = build_dense_chunk(s_table, head, maptable, cut, max_depth, i_types, gcount, last_ptr);
    o_types[chunk_num] = PTR_TYPE_DENSE; 
  } else { // VERYDENSE
    chunk_arr[chunk_num] = build_vdense_chunk(s_table, head, maptable, cut, max_depth, i_types, gcount, last_ptr);
    o_types[chunk_num] = PTR_TYPE_VERYDENSE; 
  } 

}

/** FUNCTIONS FOR BUILDING SPARSE CHUNK **/

chunk_t build_sparse_chunk(small_table_t *s_table, node_t *head, int cut, int max_depth, uint8_t *i_types, int *gcount, uint16_t *last_ptr) {
  chunk_t chunk;
  lnode_t *arr;

  // allocate space ...
  chunk.sparse.heads    = malloc(sizeof(uint8_t) * 8);
  chunk.sparse.pointers = malloc(sizeof(uint16_t) * 8);

  arr = build_array_heads(head, 8, cut);
  
  lnode_t *temp = arr;
  int i = 0;
  int j;
  while (temp != NULL) {
    chunk.sparse.heads[i] = temp->idx;
    if(temp->type == HEAD_GENUINE) {
      chunk.sparse.pointers[i] = get_nhop_idx(s_table->next_hop_table, temp->nhop, s_table->num_entries);
    } else { // consult the incoming types array to check the type of the chunk
      chunk.sparse.pointers[i] = *gcount;
      if(i_types[*gcount] == PTR_TYPE_SPARSE)
        chunk.sparse.pointers[i] |= (PTR_TYPE_SPARSE << 14);
      else if (i_types[*gcount] == PTR_TYPE_DENSE)
        chunk.sparse.pointers[i] |= (PTR_TYPE_DENSE << 14);
      else if (i_types[*gcount] == PTR_TYPE_VERYDENSE) 
        chunk.sparse.pointers[i] |= (PTR_TYPE_VERYDENSE << 14);
      *gcount = *gcount + 1;
    }
    temp = temp->next;
    i++;
  }

  j = i-1;
  while (i < 8) {
    chunk.sparse.heads[i] = chunk.sparse.heads[j];
    chunk.sparse.pointers[i] = chunk.sparse.pointers[j];
    i++;
  } 

  *last_ptr = chunk.sparse.pointers[0];//0 is always the largest

  return chunk;
}

//used only for sparse trees, 8 bit to compare is in idx
lnode_t *build_array_heads(node_t *node, int count, int cut) {
  lnode_t *temp;
  lnode_t *r;
  lnode_t *l;

  if ((count == 0) || (node->type == HEAD_GENUINE)) {
    if ((node->type != HEAD_ROOT) && (node->type != HEAD_GENUINE))
      printf("WARNING: In sparse tree, found bad node type\n");
    temp = malloc(sizeof(lnode_t));
    temp->type = node->type;
    temp->nhop = node->nhop;
    temp->idx  = (node->addr >> (24-cut)) & 0xff; 
    temp->next = NULL;
    return temp;
  }

  if(node->l != NULL)
    l = build_array_heads(node->l, count-1, cut);
  if(node->r != NULL)
    r = build_array_heads(node->r, count-1, cut);

  // can never be returned NULL
  temp = r;
  while(temp->next != NULL)
    temp = temp->next;
  temp->next = l;
  return r;
}


/** FUNCTIONS FOR BUILDING DENSE/VDENSE CHUNK **/

chunk_t build_vdense_chunk(small_table_t *s_table, node_t *head, uint16_t *maptable, int cut, int max_depth, uint8_t *i_types, int *gcount, uint16_t *last_ptr) {

  chunk_t chunk;
  cut_t *cut_i = &(chunk.dense.cut);
  uint16_t *codewords;
  int i;

  // build codewords

  cut_i->base = malloc(sizeof(uint16_t) * 4);

  cut_i->codewords = malloc(sizeof(uint16_t) * 16);

  codewords = malloc(sizeof(uint16_t) * 16);
  memset(codewords, 0, sizeof(uint16_t) * 16);
  lnode_t *ptr_list = malloc(sizeof(lnode_t) * 16);
  memset(ptr_list, 0, sizeof(lnode_t) * 16);

  rec_set_codewords(s_table, codewords, head, maptable, 8, cut, ptr_list);
  set_codewords_ptrs(s_table, cut_i, codewords, ptr_list, maptable, 4, cut, i_types, gcount, last_ptr); 

  // dense needs bases fixed

  // free used memory
  free(codewords);
  for (i = 0; i < 16; i++) {
    destroy_node(ptr_list[i].next); 
  }
  free(ptr_list);

  return chunk;
}

chunk_t build_dense_chunk(small_table_t *s_table, node_t *head, uint16_t *maptable, int cut, int max_depth, uint8_t *i_types, int *gcount, uint16_t *last_ptr) {

  chunk_t chunk;
  cut_t *cut_i = &(chunk.dense.cut);
  uint16_t *codewords;
  int i;

  // build codewords

  cut_i->base = malloc(sizeof(uint16_t));

  cut_i->codewords = malloc(sizeof(uint16_t) * 16);

  codewords = malloc(sizeof(uint16_t) * 16);
  memset(codewords, 0, sizeof(uint16_t) * 16);
  lnode_t *ptr_list = malloc(sizeof(lnode_t) * 16);
  memset(ptr_list, 0, sizeof(lnode_t) * 16);

  rec_set_codewords(s_table, codewords, head, maptable, 8, cut, ptr_list);
  set_codewords_ptrs(s_table, cut_i, codewords, ptr_list, maptable, 16, cut, i_types, gcount, last_ptr); 

  // dense needs bases fixed

  // free used memory
  free(codewords);
  for (i = 0; i < 16; i++) {
    destroy_node(ptr_list[i].next); 
  }
  free(ptr_list);

  return chunk;
}

// sets the codewords and bases and pointer table for the current chunk
void set_codewords_ptrs(small_table_t *s_table, cut_t *cut_i, uint16_t *codewords, lnode_t *ptr_list, uint16_t *maptable, int codes_per_base, int cut, uint8_t *i_types, int *gcount, uint16_t *last_ptr) {
  uint16_t *ptr_table;
  int *ptrs; 
  int base_count;
  int ptr_count;
  int n_codewords;
  int i,j;
  int curr_code;
  int ptr_off;
  uint16_t codeword_temp;
  uint16_t six, ten;
  uint16_t ptr_temp;
  lnode_t *temp; 

  if (cut == 16) { //l2
    ptr_table = s_table->l2_ptr_table;
    ptrs = &(s_table->n_l2_ptrs);
    n_codewords = 16;
  } else if (cut == 24){ //l3
    ptr_table = s_table->l3_ptr_table;
    ptrs = &(s_table->n_l3_ptrs);
    n_codewords = 16;
  } else {// l1
    ptr_table = s_table->l1_ptr_table;
    ptrs = &(s_table->n_l1_ptrs);
    n_codewords = L1_N_CODEWORDS;
  }

  base_count = *ptrs; 
  ptr_count = 0;
  
  for (i = 0; i < n_codewords; i+=codes_per_base) { // iterate over each set of codewords (one base)
    for(j = 0; j < codes_per_base; j++) {  // iterate over each codeword sharing this base
      ptr_off = ptr_count;
      curr_code = i + j;
      codeword_temp = codewords[curr_code];
      temp = ptr_list[curr_code].next;
      if ((codeword_temp == 0x0) || (codeword_temp == 0x8000)) { // encode pointer directly in codeword
        if (codeword_temp == 0x8000) { // update last_ptr
          if (temp->type == PTR_TYPE_CHUNK) { // use chunk pointer
            *last_ptr = *gcount;

            if(i_types[*gcount] == PTR_TYPE_SPARSE)
              *last_ptr = *last_ptr | (PTR_TYPE_SPARSE << 14);
            else if (i_types[*gcount] == PTR_TYPE_DENSE)
              *last_ptr = *last_ptr | (PTR_TYPE_DENSE << 14);
            else if (i_types[*gcount] == PTR_TYPE_VERYDENSE) 
              *last_ptr = *last_ptr | (PTR_TYPE_VERYDENSE << 14);

            *gcount = *gcount + 1;
          } else { // genuine head, get next hop idx
            *last_ptr = get_nhop_idx(s_table->next_hop_table, temp->nhop, s_table->num_entries);
          }
        }
        six = *last_ptr & 0x003f;
        ten = ((*last_ptr & 0xffc0) >> 6) + 676; 
        //set codeword
        cut_i->codewords[curr_code] = (six << 10) | ten;
      } // END - nhop pointer encoded directly in codeword 

      else { // pointer will be stored in pointer table
        ten = get_maptable_idx(codeword_temp, maptable); 
        six = ptr_count;
        cut_i->codewords[curr_code] = (six << 10) | ten;
        while(temp != NULL) {
          if(temp->type == PTR_TYPE_CHUNK) {
            ptr_temp = *gcount;
            //printf("PTRCHUNK: TYPE: %d PTRTMP: %x IDX: %d\n", i_types[*gcount], ptr_temp, *ptrs);
            if(i_types[*gcount] == PTR_TYPE_SPARSE)
              ptr_temp |= (PTR_TYPE_SPARSE << 14);
            else if (i_types[*gcount] == PTR_TYPE_DENSE)
              ptr_temp |= (PTR_TYPE_DENSE << 14);
            else if (i_types[*gcount] == PTR_TYPE_VERYDENSE) 
              ptr_temp |= (PTR_TYPE_VERYDENSE << 14);
            *gcount = *gcount + 1;
          }
          else {
            ptr_temp = get_nhop_idx(s_table->next_hop_table, temp->nhop, s_table->num_entries);
            //printf("PTR PTRTMP: %x IDX: %d\n",  ptr_temp, *ptrs);
          }

          ptr_table[*ptrs] = ptr_temp;
          *last_ptr = ptr_temp; 
          *ptrs = *ptrs + 1;
          ptr_count++; 
          temp = temp->next; 
        }
      } // END - pointer stored in pointer table

    } // END - Iterate over codewords in base
  
    cut_i->base[i/codes_per_base] = base_count;
    base_count += ptr_count;
    ptr_count = 0;
 
  } // END - Iterate over each base

}

// sets codewords linked list of pointers per codeword (needed to detect 0 and 1 next hop entries)
void rec_set_codewords(small_table_t *s_table, uint16_t *codewords, node_t *node, uint16_t *maptable, int count, int cut, lnode_t* ptrs) {
  uint16_t addr;
  int idx;
  uint8_t bit_num;
  
  if (cut == 16) { //l2
    addr = (node->addr & 0x0000ff00) >> 8;
  } else if (cut == 24){ //l3
    addr = (node->addr & 0x00000ff);
  } else {// l1
    addr = (node->addr & 0xffff0000) >> 16;
  }

  if ((count == 0) || (node->type == HEAD_GENUINE)) { // found a head

    //if(cut == 0) {
    //  printf("COUNT: %d IDX: %d BIT: %d Type: %d Addr: %x\n", count, addr>>4, addr & 0x000f, node->type, node->addr);
    //}

    idx = addr >> 4;
    bit_num = addr & 0x000f;
    
    //set a bit for this head
    codewords[idx] |= (0x8000 >> bit_num); 

    if (node->type == HEAD_GENUINE) {
      add_node(&ptrs[idx], bit_num, PTR_TYPE_NH, node->nhop);
    }
    else if (node->type == HEAD_ROOT) {
      add_node(&ptrs[idx], bit_num, PTR_TYPE_CHUNK, node->nhop);
    }

  } else { // Recurse
    if (node->l != NULL)
      rec_set_codewords(s_table, codewords, node->l, maptable, count-1, cut, ptrs);
    if (node->r != NULL)
      rec_set_codewords(s_table, codewords, node->r, maptable, count-1, cut, ptrs);
  }
}


void build_s_table_map_table(small_table_t *s_table,uint16_t *maptable) {
  int i,j;
  uint16_t bvect, mask;  
  uint8_t count;
  uint8_t first, second;

  for(i = 0; i < 676; i++) {
    count = 0;
    bvect = maptable[i];
    mask = 0x4000;
    first = 0;
    second = 0;
    for(j = 0; j < 8; j++) {
      if(j!=0) {
        if(bvect & mask) 
          count++;
        first = count;
        mask = mask >> 1;
      }
      if(bvect & mask) 
        count++;
      second = count;
      mask = mask >> 1;
      s_table->maptable[i][j] = (first << 4) | (second & LBYTE);
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

void destroy_node(lnode_t *node) {
  lnode_t *temp;

  if (node == NULL) return;
  
  while (node != NULL) {
    temp = node->next;
    free(node);
    node = temp;
  }
}


void complete_tree(node_t *node, node_t *ancestor, int depth, uint32_t addr) {
  if (node->type == HEAD_GENUINE) {
    ancestor = node;
    if((node->r != NULL) && (node->l != NULL)) {
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
      //printf("Level %d: Completing LEFT addr: %x with new %x\n", depth, addr,addr | (0x80000000 >> depth) );
      complete_tree(node->r, ancestor, depth+1, addr | (0x80000000 >> depth));
    } else { // node->r
      node->r = new_node();
      node->r->type = HEAD_GENUINE;
      node->r->addr = addr | (0x80000000 >> depth);
      node->r->nhop = ancestor->nhop;
      //printf("Level %d: Completing RIGHT addr: %x with new %x\n", depth, addr,addr | (0x80000000 >> depth) );
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


/*
 *
 *  Code for searching the Lookup Table
 *
 */

uint32_t lookup_small_table(uint32_t dest_ip, void *table) {
  small_table_t *s_table;
  chunk_t *chunk;
  uint16_t curr_ptr;
  uint8_t ptr_type;
  uint8_t chunk_addr;

  s_table = (small_table_t *)table;

  curr_ptr = get_ptr_l1(s_table, dest_ip >> 16);
  ptr_type = curr_ptr >> 14;

  // Search L2
  if (ptr_type == PTR_TYPE_NH) { 
    l1_found++;
    return s_table->next_hop_table[curr_ptr];
  } else { //ptr to lower chunk
    chunk = &(s_table->l2[curr_ptr & 0x3fff]);
    chunk_addr = (dest_ip & 0x0000ff00) >> 8;
    if (ptr_type == PTR_TYPE_SPARSE) 
      curr_ptr = get_ptr_sparse(chunk, chunk_addr);
    else if (ptr_type == PTR_TYPE_DENSE) 
      curr_ptr = get_ptr_dense(s_table, chunk, chunk_addr, 2);
    else if (ptr_type == PTR_TYPE_VERYDENSE) 
      curr_ptr = get_ptr_vdense(s_table, chunk, chunk_addr, 2);
  }
  ptr_type = curr_ptr >> 14; 

  // Search L3
  if (ptr_type == PTR_TYPE_NH) { 
    l2_found++;
    return s_table->next_hop_table[curr_ptr];
  } else { //ptr to lower chunk
    chunk = &(s_table->l3[curr_ptr & 0x3fff]);
    chunk_addr = dest_ip & 0x000000ff;
    if (ptr_type == PTR_TYPE_SPARSE) 
      curr_ptr = get_ptr_sparse(chunk, chunk_addr);
    else if (ptr_type == PTR_TYPE_DENSE) 
      curr_ptr = get_ptr_dense(s_table, chunk, chunk_addr, 3);
    else if (ptr_type == PTR_TYPE_VERYDENSE) 
      curr_ptr = get_ptr_vdense(s_table, chunk, chunk_addr, 3);
  }
  l3_found++;
  return s_table->next_hop_table[curr_ptr];
}

uint16_t get_ptr_l1(small_table_t *s_table, uint16_t addr) {
  uint16_t bix, ix, bit, pix;
  uint16_t codeword;
  uint16_t base;
  uint16_t ten, six;
  uint16_t ptr;
  uint16_t maptable_off;

  bix = (addr & 0xffc0) >> 6;
  ix  = (addr & 0xfff0) >> 4;
  bit = addr & 0x000f; 

  codeword  = s_table->l1.codewords[ix];
  base      = s_table->l1.base[bix];
  six = codeword >> 10;
  ten = codeword & 0x03ff;

  if (ten > 675) { // encoded directly into codeword
    ptr = six | ((ten-676) << 6);
  } 
  else {
    maptable_off = s_table->maptable[ten][bit >> 1];
    maptable_off = (bit & 0x0001) ? maptable_off & 0x000f : (maptable_off & 0x00f0) >> 4;
    pix = six + base + maptable_off;
    ptr = s_table->l1_ptr_table[pix];
  }

  return ptr; 
}

uint16_t get_ptr_sparse(chunk_t *chunk, uint8_t addr) {
  int i;

  if (addr >= chunk->sparse.heads[3]) { // search higher addresses
    for (i = 0; i < 4; i++) {
      if (addr >= chunk->sparse.heads[i])
        return chunk->sparse.pointers[i];
    }
  } else { // search lower addresses
    for (i = 4; i < 8; i++) {
      if (addr >= chunk->sparse.heads[i])
        return chunk->sparse.pointers[i];
    }
  }
  return chunk->sparse.pointers[7];
}

uint16_t get_ptr_dense(small_table_t *s_table, chunk_t *chunk, uint8_t addr, int level) {
  uint16_t ix, bit, pix;
  uint16_t codeword;
  uint16_t base;
  uint16_t ten, six;
  uint16_t ptr;
  uint16_t maptable_off;
  uint16_t *ptr_table;

  ix  = (addr & 0xf0) >> 4;
  bit = addr & 0x0f;

  if (level == 2)
    ptr_table = s_table->l2_ptr_table;
  else
    ptr_table = s_table->l3_ptr_table;

  codeword  = chunk->dense.cut.codewords[ix];
  base      = chunk->dense.cut.base[0];

  six = codeword >> 10;
  ten = codeword & 0x03ff;

  if (ten > 675) { // encoded directly into codeword
    ptr = six | ((ten-676) << 6);
  } 
  else {
    maptable_off = s_table->maptable[ten][bit >> 1];
    maptable_off = (bit & 0x0001) ? maptable_off & 0x000f : (maptable_off & 0x00f0) >> 4;
    pix = six + base + maptable_off;
    ptr = ptr_table[pix];
  }

  return ptr; 
}

uint16_t get_ptr_vdense(small_table_t *s_table, chunk_t *chunk, uint8_t addr, int level) {
  uint16_t ix, bit, pix, bix;
  uint16_t codeword;
  uint16_t base;
  uint16_t ten, six;
  uint16_t ptr;
  uint16_t maptable_off;
  uint16_t *ptr_table;

  ix  = (addr & 0xf0) >> 4;
  bix = (addr & 0xc0) >> 6;
  bit = addr & 0x0f;

  if (level == 2)
    ptr_table = s_table->l2_ptr_table;
  else
    ptr_table = s_table->l3_ptr_table;

  codeword  = chunk->dense.cut.codewords[ix];
  base      = chunk->dense.cut.base[bix];

  six = codeword >> 10;
  ten = codeword & 0x03ff;

  if (ten > 675) { // encoded directly into codeword
    ptr = six | ((ten-676) << 6);
  } 
  else {
    maptable_off = s_table->maptable[ten][bit >> 1];
    maptable_off = (bit & 0x0001) ? maptable_off & 0x000f : (maptable_off & 0x00f0) >> 4;
    pix = six + base + maptable_off;
    ptr = ptr_table[pix];
  }

  return ptr; 

}
