/*
 *
 *  Created By: Nick Pfister
 *
 *  Description:
 *
 */
#ifndef SCALABLE_TABLES_H
#define SCALABLE_TABLES_H

#include "utility.h"
//#include "np_hashtable.h"

//defines

//data structures

//initial "1st pass" trie datastruct type for nodes of trie
typedef struct prefix_len_below_t prefix_len_below_t;
struct prefix_len_below_t { //linked list node for prefixes lengths below a particular trie node
	uint32_t prefix_len;//prefix length below this trie node
	prefix_len_below_t * next_prefix_len_below;
};
typedef struct trie_node_t trie_node_t;
struct trie_node_t {
	uint32_t n_prefix_below;//number of prefixes stored below this node
	prefix_len_below_t * prefix_len_below;//linked list of prefixes lengths stored below this trie node
	uint32_t prefix;//this node's prefix
	uint32_t prefixlen;//this node's prefix length
	uint32_t mask;//example --> 0xFFFF8000 (prefixlen=17)
	uint32_t real_prefix;//not a marker trie node

	trie_node_t * left;
	trie_node_t * right;
};
	

//functions

//per paper's recommended rope based scalable table build procedure,
//second pass to build ropes and hash tables, using conventional trie from first pass
//*****small_table_t *build_scalable_table(route_table_entry_t *table, int table_size);

//per paper's recommended rope based scalable table build procedure, first pass builds a conventional trie
trie_node_t * build_trie_table(route_table_entry_t * table, int num_entries);//first pass of building ropes and array of hash tables
//build_trie_table helper functions
trie_node_t * insert_trie_node(trie_node_t * trie, route_table_entry_t * table_entry, uint32_t curr_level);
prefix_len_below_t * insert_prefix_len_below(prefix_len_below_t * prefix_len_below, route_table_entry_t * table_entry,uint32_t * duplicate);
void destroy_prefix_len_below(prefix_len_below_t * prefix_len_below);

//destroy data structure functions
//destroy_scalable_table()
void destroy_trie_table(trie_node_t * trie);

#endif