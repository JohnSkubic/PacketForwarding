/*
 *
 *  Created By: Nick Pfister
 *
 *  Description: "Scalable High Speed Routing Lookups"
 *               part of implementation of http://conferences.sigcomm.org/sigcomm/1997/papers/p182.pdf
 */
#ifndef SCALABLE_TABLES_H
#define SCALABLE_TABLES_H

#include "utility.h"

//****defines****
#define MAX_BUCKETS 65536 //2^16=65536 for now

//****data structures****

//TRIES
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
	uint32_t next_hop_addr;//only populated if real prefix, bmp in scalable

	trie_node_t * left;
	trie_node_t * right;
};
//SCALABLE TABLES
//buckets are nodes of scalable tables, inserted in hash tables
//bucket type
enum bucket_type_t {
	prefix,
	marker,
	both, //prefix and marker
	empty //empty - not really used since moving to array of pointers to buckets
};
typedef enum bucket_type_t bucket_type_t;
//individual bucket of hash table
struct bucket_t {
	bucket_t * nxt_bucket;//linked list for collision resolution
	bucket_type_t bucket_type;//prefix, marker, or both, or empty
	uint32_t prefix;//field searched against for match
	//only filled if bucket type is marker
	uint32_t bmp;//best matching prefix -- set by pre-computation, alleviates backtracking
	//forwarding info - only filled if bucket type is prefix or both
	uint32_t nxt_hop_addr;	
	//next search tree to use -- fill in when implementing ropes/mutated binary search
	rope_t * new_rope;//new rope to use for search (hash success, but marker)
};
typedef struct bucket_t bucket_t;
struct rope_t {
	uint32_t level;
	rope_t * nxt_rope_node;
}
typedef struct rope_t rope_t;
//HASH TABLES
//per prefix-level struct
struct htable_t {
	//hash table statistics
	uint32_t level;//number of buckets cannot exceed 2^(prefix level)
	uint32_t num_buckets;//current buckets in htable
	uint32_t shamt;//shift amount to hash on, compute once, not on every hash call
	uint32_t mask;//mask to obtain appropriate MSBs off of prefix for level of hashtable
	uint32_t num_entries;//current entries in htable
	uint32_t num_collisions;//metric for resizing decision
	
	//actual hash table
	bucket ** buckets;//ptr to array of buckets[num_entries]
};
typedef struct htable_t htable_t;
	
//****functions****

//Trie functions
//per paper's recommended rope based scalable table build procedure, first pass builds a conventional trie
trie_node_t * build_trie_table(route_table_entry_t * table, int num_entries);//first pass of building ropes and array of hash tables
trie_node_t * insert_trie_node(trie_node_t * trie, route_table_entry_t * table_entry, uint32_t curr_level);//build_trie_table helper functions
prefix_len_below_t * insert_prefix_len_below(prefix_len_below_t * prefix_len_below, route_table_entry_t * table_entry,uint32_t * duplicate);
void destroy_prefix_len_below(prefix_len_below_t * prefix_len_below);
void destroy_trie_table(trie_node_t * trie);

//Scalable table functions
//per paper's recommended rope-based scalable table build procedure,
//second pass to build ropes and hash tables, using conventional trie from first pass
htable_t ** build_scalable_table(route_table_entry_t * table, int num_entries);
htable_t ** init_scalable_htables(uint32_t num_levels);//initializes array of hash tables,32 levels for IPv4, BEWARE
void destroy_scalable_htables(htable_t ** scalable_htables, uint32_t num_levels);
//ropes guide level search for scalable tables
void destroy_rope(rope_t * rope);

//Custom hash table functions
//custom/tightly integrated to scalable tables
//valid prefix_levevls are 1 to 32 inclusive
htable_t * htable_create (uint32_t prefix_level);
void htable_delete(htable_t * htable);
void htable_llist_delete(bucket_t * bucket);//delete collision resolution llist at an index in bucket ptr array
//prefix must match format for corresponding prefix level
void htable_insert(htable_t * htable, uint32_t prefix);//prefix must be masked according to level already
bucket_t * htable_insert_llist(bucket_t * bucket, uint32_t index);//linked list insert for collision resolution0
//key is prefix, masked to length of corresponding prefix level
//returns index into hast table
uint32_t htable_hash(htable_t * htable, uint32_t key);
//uses index to search entry or linked list at index for prefix
bucket_t * htable_search(htable_t * htable, , bucket_type_t btype, uint32_t prefix, uint32_t bmp, uint32_t nxt_hop_addr, rope_t * rope);
bucket_t * htable_search_llist(bucket_t * bucket_ll, bucket * n_bucket, htable_t * htable);//index=htable_hash(prefix), bucket_t*=htable[prefixlevel]->buckets[]

//*****FUTURE UPGRADE*****
//htable_t* htable_resize(htable_t * htable);//doubles the size of buckets, copies old bucket entries into correct new buckets, deletes old buckets
//currently working off MAX_BUCKETS during/from initialization/htable_creat()
//not bad for power of 2 nature of scalable tables, max unique entries are 2^prefix_level
//hashtable memory usage alleviated since moving to array of pointers to buckets,
//unused buckets only occupy a NULL pointer instead of the entire bucket_t struct

#endif