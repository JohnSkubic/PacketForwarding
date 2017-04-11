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

#define CODEWORD_6_BM   0xfc00
#define CODEWORD_10_BM  0x03ff


//L2 L3
#define IX_2_3_BM   0x000000f0
#define BIX_2_3_BM  0x000000c0
#define BIT_2_3_BM  0x0000000f
#define L3_MASK     0xffffff00
#define L2_MASK     0xffff0000

/* Data structure for 16 depth cut */

typedef struct cut_t {
  uint16_t *pointers; 
  uint16_t *codewords;
  uint16_t *base;
} cut_t;


/* Data structure for level 2 and 3 chunks */

#define CHUNK_TYPE_SPARSE     0 
#define CHUNK_TYPE_DENSE      1
#define CHUNK_TYPE_VERYDENSE  2

typedef struct chunk_sparse_t {
  uint8_t type;
  uint8_t num_heads;
  uint8_t *heads;
  uint32_t *pointers;
} chunk_sparse_t;

typedef struct chunk_dense_t {
  uint8_t type;
  cut_t   cut;
} chunk_dense_t;

typedef union chunk_t {
  chunk_sparse_t  sparse;
  chunk_dense_t   dense;
  chunk_dense_t  vdense; 
} chunk_t;

/* Small table Data Structure */

typedef struct small_table_t {
  uint32_t *next_hop_table;
  uint8_t maptable[676][8]; // Each index contains 2 ptrs (4 bits)
  cut_t   l1;
  chunk_t *l2;
  chunk_t *l3;
} small_table_t;

small_table_t *build_small_table(route_table_entry_t *table, int table_size);
void destroy_small_table(small_table_t *table);

chunk_t *build_sparse_chunk(route_table_entry_t *table, uint32_t *pointers,  int size, int level);
chunk_t *build_dense_chunk(route_table_entry_t *table,  uint32_t *pointers,  int size);
chunk_t *build_vdense_chunk(route_table_entry_t *table, uint32_t *pointers,  int size);

uint32_t lookup_small_table(uint32_t dest_ip, void *table);
uint32_t get_chunk_ptr(uint32_t dest_ip, uint32_t level, uint32_t pointer, small_table_t *s_table);

#endif
