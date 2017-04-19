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
    printf("ADDR: %x NHOP: %d\n", table[i].dest_addr.address, table[i].next_hop_addr);
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
  * Build L3
  *
  */

  printf("\nBUILDING LEVEL 3\n\n");

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
  build_chunk_trees_rec(s_table, tree, 24, 32, 0, 0, NULL, types_l3, &count, &last_ptr); // builds the tree starting at the give cut
  

  // free l3 memory

  /*
  *
  * Build L2
  *
  */

  printf("\nBUILDING LEVEL 2\n\n");

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
  build_chunk_trees_rec(s_table, tree, 16, 24, 0, 0, types_l3, types_l2, &count, &last_ptr);

  /* 
  *
  * Build L1 
  *
  */
  
  printf("\nBUILDING LEVEL 1\n\n");

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

  rec_set_codewords(s_table, codewords, tree, 16, 0, ptrs);
  set_codewords_ptrs(s_table, &(s_table->l1), codewords, ptrs, 4, 0, types_l2, &count, &last_ptr); 

  return NULL;
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

int build_chunk_trees_rec(small_table_t *s_table, node_t *head, int cut, int max_depth, int chunk_num, int clevel, uint8_t *i_types, uint8_t *o_types, int *gcount, uint16_t *last_ptr) {
  if (clevel < cut) {
    if (head->l != NULL)
      chunk_num += build_chunk_trees_rec(s_table, head->l, cut, max_depth, chunk_num, clevel+1, i_types, o_types, gcount, last_ptr);
    if (head->r != NULL)
      chunk_num += build_chunk_trees_rec(s_table, head->r, cut, max_depth, chunk_num, clevel+1, i_types, o_types, gcount, last_ptr);
  }
  else if ((clevel == cut) && (head->type == HEAD_ROOT)){
    build_chunk_trees(s_table, head, cut, max_depth, chunk_num, i_types, o_types, gcount, last_ptr);
    chunk_num++;
  }
  return chunk_num;
}

void build_chunk_trees(small_table_t *s_table, node_t *head, int cut, int max_depth, int chunk_num, uint8_t *i_types, uint8_t *o_types, int *gcount, uint16_t *last_ptr) {
  printf("Building chunk number: %d\n", chunk_num); 
  int num_ptrs = 0;
  int num_chunks = 0;

  chunk_t *chunk_arr = NULL;

  //choose the correct level
  if (cut == 16)
    chunk_arr = s_table->l2;
  else if (cut == 24)
    chunk_arr = s_table->l3;
  
  find_level_sizes(head, cut, cut, max_depth, &num_chunks, &num_ptrs);

  printf("cut: %d max %d CHUNKS %d PTRS %d\n", cut, max_depth, num_chunks, num_ptrs);

  if (num_ptrs <= 8) { //SPARSE
    printf("Building sparse chunk\n");
    chunk_arr[chunk_num] = build_sparse_chunk(s_table, head, cut, max_depth, i_types, gcount, last_ptr);
    o_types[chunk_num] = PTR_TYPE_SPARSE; 
  } else if (num_ptrs <= 64) { //DENSE
    printf("Building dense chunk\n");
    chunk_arr[chunk_num] = build_dense_chunk(s_table, head, cut, max_depth, i_types, gcount, last_ptr);
    o_types[chunk_num] = PTR_TYPE_DENSE; 
  } else { // VERYDENSE
    printf("Building very dense chunk\n");
    chunk_arr[chunk_num] = build_vdense_chunk(s_table, head, cut, max_depth, i_types, gcount, last_ptr);
    o_types[chunk_num] = PTR_TYPE_VERYDENSE; 
  } 

}

/** FUNCTIONS FOR BUILDING SPARSE CHUNK **/

chunk_t build_sparse_chunk(small_table_t *s_table, node_t *head, int cut, int max_depth, uint8_t *i_types, int *gcount, uint16_t *last_ptr) {
  chunk_t chunk;
  lnode_t *arr;
  uint16_t *ptr_table;
  int *ptrs;

  if (cut == 16) {
    ptr_table = s_table->l2;
    ptrs = &(s_table->n_l2_ptrs);
  } else {
    ptr_table = s_table->l3;
    ptrs = &(s_table->n_l3_ptrs);
  }

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

chunk_t build_vdense_chunk(small_table_t *s_table, node_t *head, int cut, int max_depth, uint8_t *i_types, int *gcount, uint16_t *last_ptr) {

  chunk_t chunk;
  cut_t *cut_i = &(chunk.dense.cut);
  uint16_t *ptr_table;
  int *ptrs;
  uint16_t *codewords;
  int i;

  if (cut == 16) {
    ptr_table = s_table->l2;
    ptrs = &(s_table->n_l2_ptrs);
  } else {
    ptr_table = s_table->l3;
    ptrs = &(s_table->n_l3_ptrs);
  }

  // build codewords

  cut_i->base = malloc(sizeof(uint16_t) * 4);

  cut_i->codewords = malloc(sizeof(uint16_t) * 16);

  codewords = malloc(sizeof(uint16_t) * 16);
  memset(codewords, 0, sizeof(uint16_t) * 16);
  lnode_t *ptr_list = malloc(sizeof(lnode_t) * 16);
  memset(ptr_list, 0, sizeof(lnode_t) * 16);

  rec_set_codewords(s_table, codewords, head, 8, cut, ptr_list);
  set_codewords_ptrs(s_table, cut_i, codewords, ptr_list, 4, cut, i_types, gcount, last_ptr); 

  // dense needs bases fixed

  // free used memory
  free(codewords);
  for (i = 0; i < 16; i++) {
    //destroy_node(ptr_list[i].next); //TODO: This causes segfault
  }
  free(ptr_list);

}

chunk_t build_dense_chunk(small_table_t *s_table, node_t *head, int cut, int max_depth, uint8_t *i_types, int *gcount, uint16_t *last_ptr) {

  chunk_t chunk;
  cut_t *cut_i = &(chunk.dense.cut);
  uint16_t *ptr_table;
  int *ptrs;
  uint16_t *codewords;
  int i;

  if (cut == 16) {
    ptr_table = s_table->l2;
    ptrs = &(s_table->n_l2_ptrs);
  } else {
    ptr_table = s_table->l3;
    ptrs = &(s_table->n_l3_ptrs);
  }

  // build codewords

  cut_i->base = malloc(sizeof(uint16_t));

  cut_i->codewords = malloc(sizeof(uint16_t) * 16);

  codewords = malloc(sizeof(uint16_t) * 16);
  memset(codewords, 0, sizeof(uint16_t) * 16);
  lnode_t *ptr_list = malloc(sizeof(lnode_t) * 16);
  memset(ptr_list, 0, sizeof(lnode_t) * 16);

  rec_set_codewords(s_table, codewords, head, 8, cut, ptr_list);
  set_codewords_ptrs(s_table, cut_i, codewords, ptr_list, 16, cut, i_types, gcount, last_ptr); 

  // dense needs bases fixed

  // free used memory
  free(codewords);
  for (i = 0; i < 16; i++) {
    //destroy_node(ptr_list[i].next); //TODO: This causes segfault
  }
  free(ptr_list);

}

// sets the codewords and bases and pointer table for the current chunk
void set_codewords_ptrs(small_table_t *s_table, cut_t *cut_i, uint16_t *codewords, lnode_t *ptr_list, int codes_per_base, int cut, uint8_t *i_types, int *gcount, uint16_t *last_ptr) {
  uint16_t *ptr_table;
  uint16_t *ptrs; 
  int base_count;
  int ptr_count;
  int n_codewords;
  int codewords_per_base;
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

  if (*ptrs == 0) 
    base_count = 0;
  else
    base_count = *ptrs - 1;
  
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
        ten = get_maptable_idx(codeword_temp, s_table->maptable);
        six = ptr_count;
        cut_i->codewords[curr_code] = (six << 10) | ten;
        while(temp != NULL) {
          if(temp->type == PTR_TYPE_CHUNK) {
            ptr_temp = *gcount;
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
          }
          ptr_table[*ptrs] = ptr_temp;
          *last_ptr = ptr_temp; 
          *ptrs = *ptrs + 1;
          ptr_count++; 
          temp = temp->next; 
        }
      } // END - pointer stored in pointer table

    } // END - Iterate over codewords in base
   
    cut_i->base[i] = base_count;
    base_count += ptr_count;
    ptr_count = 0;
 
  } // END - Iterate over each base

}

// sets codewords linked list of pointers per codeword (needed to detect 0 and 1 next hop entries)
void rec_set_codewords(small_table_t *s_table, uint16_t *codewords, node_t *node, int count, int cut, lnode_t* ptrs) {
  lnode_t *temp;
  lnode_t *r;
  lnode_t *l;
  uint8_t addr;
  int idx;
  uint8_t bit_num;
  
  if (cut == 16) { //l2
    //ptr_table = s_table->l2_ptr_table;
    //ptrs = &(s_table->n_l2_ptrs);
    addr = (node->addr & 0x0000ff00) >> 8;
  } else if (cut == 24){ //l3
    //ptr_table = s_table->l3_ptr_table;
    //ptrs = &(s_table->n_l3_ptrs);
    addr = (node->addr & 0x00000ff);
  } else {// l1
    //ptr_table = s_table->l1_ptr_table;
    //ptrs = &(s_table->n_l1_ptrs);
    addr = (node->addr & 0xffff0000) >> 16;
  }

  if ((count == 0) || (node->type == HEAD_GENUINE)) { // found a head
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

    /*
    
    // add entry to pointer table and increment pointer counter
    if ( node->type == HEAD_GENUINE) {
      ptr_table[*ptrs] = get_nhop_idx(s_table->next_hop_table, node->nhop, s_table->num_entries);
    } else if (node->type == HEAD_ROOT) {
      ptr_table[*ptrs] = *gcount;
      if(i_types[*gcount] == PTR_TYPE_SPARSE)
        ptr_table[*ptrs] |= (PTR_TYPE_SPARSE << 14);
      else if (i_types[*gcount] == PTR_TYPE_DENSE)
        ptr_table[*ptrs] |= (PTR_TYPE_DENSE << 14);
      else if (i_types[*gcount] == PTR_TYPE_VERYDENSE) 
        ptr_table[*ptrs] |= (PTR_TYPE_VERYDENSE << 14);
      *gcount = *gcount + 1;
    }
    *ptrs = *ptrs + 1;*/
  } else { // Recurse
    if (node->l != NULL)
      rec_set_codewords(s_table, codewords, node->l,count-1, cut, ptrs);
    if (node->r != NULL)
      rec_set_codewords(s_table, codewords, node->r,count-1, cut, ptrs);
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
    mask = 0x8000;
    for(j = 0; j < 8; j++) {
      if(bvect & mask) 
        count++;
      first = count;
      mask = mask >> 1;
      if(bvect & mask) 
        count++;
      second = count;
      mask = mask >> 1;
      s_table->maptable[i][j] = (first << 4) | (second & LBYTE);
    }    
  }
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

void destroy_node(lnode_t *node) {
  lnode_t *temp;

  if (node == NULL) return;
  
  temp = node->next;
  while (node != NULL) {
    free(node);
    node = temp;
    temp = node->next;
  }
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
