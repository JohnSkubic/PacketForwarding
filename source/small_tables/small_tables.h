/*
 *
 *  Created By: John Skubic 
 *
 *  Description:
 *
 */

#ifndef SMALL_TABLES_H
#define SMALL_TABLES_H

#include "utility.h"

#define HEAD_PTR_TYPE_MASK  0xc000
#define HEAD_PTR_PTR_MASK   0x3fff

// L1
#define IX_BM   0xfff00000
#define BIX_BM  0xffc00000
#define BIT_BM  0x000f0000

#define CODEWORD_6_BM   0x003f
#define CODEWORD_10_BM  0xffc0


//L2 L3
#define IX_2_3_BM   0x000000f0
#define BIX_2_3_BM  0x000000c0
#define BIT_2_3_BM  0x0000000f
#define L3_MASK     0xffffff00
#define L2_MASK     0xffff0000

/* Data structure for 16 depth cut */

#define L1_N_CODEWORDS  4096
#define L1_N_BASES      1024

typedef struct cut_t {
  uint16_t *codewords;
  uint16_t *base;
} cut_t;

uint16_t get_codeword_off(uint16_t codeword);
uint16_t get_codeword_idx(uint16_t codeword);
uint16_t set_codeword_off(uint16_t codeword, uint16_t off);
uint16_t set_codeword_idx(uint16_t codeword, uint16_t idx);

/* Data structure for level 2 and 3 chunks */

// Pointer types (upper 2 bits of 16 bit ptrs)
#define PTR_TYPE_NH         0
#define PTR_TYPE_SPARSE     1 
#define PTR_TYPE_DENSE      2
#define PTR_TYPE_VERYDENSE  3

typedef struct chunk_sparse_t {
  uint32_t *heads;
  uint16_t *pointers;
} chunk_sparse_t;

typedef struct chunk_dense_t {
  cut_t   cut;
} chunk_dense_t;

typedef union chunk_t {
  chunk_sparse_t  sparse;
  chunk_dense_t   dense;
} chunk_t;

/* Small table Data Structure */

typedef struct small_table_t {
  uint32_t *next_hop_table;
  uint32_t num_entries;
  uint8_t maptable[676][8]; // Each index contains 2 ptrs (4 bits)
  cut_t   l1;
  chunk_t *l2;
  chunk_t *l3;
  uint16_t *l1_ptr_table;
  uint16_t *l2_ptr_table;
  uint16_t *l3_ptr_table;
} small_table_t;

small_table_t *build_small_table(route_table_entry_t *table, int table_size);
void destroy_small_table(small_table_t *table);


#define HEAD_ROOT       0
#define HEAD_GENUINE    1
#define HEAD_MEMBER     2
#define HEAD_UNDEF      3
#define HEAD_TREE_ROOT  4

//  building tree
typedef struct node_t {
    uint8_t type; // type of head 
    uint32_t addr;
    uint32_t nhop;
    struct node_t *l; 
    struct node_t *r; 
} node_t;

typedef struct lnode_t {
  uint8_t idx;
  uint8_t type;
  uint32_t nhop;
  struct lnode_t *next;
} lnode_t;

void add_node(lnode_t *head, uint8_t idx, uint8_t type, uint32_t nhop);
node_t *get_node_by_idx(lnode_t *head, uint8_t idx);

uint16_t get_nhop_idx(uint32_t *nhop_table, uint32_t nhop, int size);

node_t *new_node();
void complete_tree(node_t *node, node_t *ancestor, int depth, uint32_t addr);
void build_L1_codewords(node_t *node, uint16_t *codewords, lnode_t *ptrs, int level);
void set_L1_codeword_base(uint16_t *codewords, lnode_t *ptrs, uint16_t *maptable, small_table_t *s_table);

uint32_t lookup_small_table(uint32_t dest_ip, void *table);
uint32_t get_chunk_ptr(uint32_t dest_ip, uint32_t level, uint32_t pointer, small_table_t *s_table);
uint16_t *build_map_table();

#endif
