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
#define MAX_BUCKETS 4096//8192//65536 //2^16=65536 for now

//****data structures****

//TRIES
//initial "1st pass" trie datastruct type for nodes of trie
typedef struct trie_node_t trie_node_t;
struct trie_node_t {
	uint32_t n_prefix_below;//number of prefixes stored below this node
	uint32_t prefix_len_below;//bit field of prefixes lengths stored below this trie node
	uint32_t prefix;//this node's prefix
	uint32_t prefixlen;//this node's prefix length
	uint32_t mask;//example --> 0xFFFF8000 (prefixlen=17)
	uint32_t real_prefix;//not a marker trie node
	uint32_t nxt_hop_addr;//only populated if real prefix, bmp in scalable

	trie_node_t * left;
	trie_node_t * right;
};
//SCALABLE TABLES
//buckets are nodes of scalable tables, inserted in hash tables
//bucket type
typedef enum bucket_type_t {
	prefix_t=0,
	marker_t,
	both_t, //prefix and marker
	empty_t //empty - not really used since moving to array of pointers to buckets
} bucket_type_t;
//individual bucket of hash table
typedef struct bucket_t bucket_t;
struct bucket_t {
	bucket_t * nxt_bucket;//linked list for collision resolution
	bucket_type_t bucket_type;//prefix, marker, or both, or empty
	uint32_t prefix;//field searched against for match
	//forwarding info - only filled if bucket type is prefix or both
	//else it is the nxt hop of the previous best matching prefix
	uint32_t nxt_hop_addr;	
	//next search tree to use -- fill in when implementing ropes/mutated binary search
	uint32_t new_rope;//new rope to use for search (hash success, but marker)
};
//HASH TABLES
//per prefix-level struct
typedef struct htable_t htable_t;
struct htable_t {
	//hash table statistics
	uint32_t level;//number of buckets cannot exceed 2^(prefix level)
	uint32_t num_buckets;//current buckets in htable
	uint32_t shamt;//shift amount to hash on, compute once, not on every hash call
	uint32_t mask;//mask to obtain index into hashtable off of prefix
	uint32_t lmask;//mask for prefix MSBs to include at level
	uint32_t num_entries;//current entries in htable
	uint32_t num_collisions;//metric for resizing decision
	
	//actual hash table
	bucket_t ** buckets;//ptr to array of buckets[num_entries]
};
typedef struct scalable_table_t scalable_table_t;
struct scalable_table_t{
	htable_t ** scalable_htables;
	uint32_t init_rope;
	uint32_t default_entry_nxt_hop;
};
	
//****functions****

//Trie functions
//per paper's recommended rope based scalable table build procedure, first pass builds a conventional trie
trie_node_t * build_trie_table(route_table_entry_t * table, int num_entries, int * default_entry_nxt_hop);//first pass of building ropes and array of hash tables
trie_node_t * insert_trie_node(trie_node_t * trie, route_table_entry_t * table_entry, uint32_t curr_level,uint32_t bmp_nxthop);//build_trie_table helper functions
void insert_prefix_len_below(uint32_t * prefix_len_below, route_table_entry_t * table_entry,uint32_t * duplicate);
uint32_t level_to_mask(uint32_t level);//prefix level to bit field mask
void destroy_trie_table(trie_node_t * trie);
//transform trie to scalable table -- trie output fxs

//Scalable table functions
//per paper's recommended rope-based scalable table build procedure,
//second pass to build ropes and hash tables, using conventional trie from first pass
scalable_table_t * build_scalable_table(trie_node_t * trie, int num_entries);
htable_t ** init_scalable_htables(uint32_t num_levels);//initializes array of hash tables,32 levels for IPv4, BEWARE
void destroy_scalable_table(scalable_table_t * scalable_table);

//ropes guide level search for scalable tables
uint32_t prefix_len_below_to_rope(uint32_t prefix_len_below, uint32_t max_depth);
void trie_level_read_scalable_insert(trie_node_t *, uint32_t prefixlevel, htable_t ** scalable_htables, uint32_t max_depth, uint32_t bmp_nxthop);//walk a trie level, insert into scalable t
uint32_t nxt_search_level(uint32_t * rope);

//pièce de résistance
uint32_t lookup_scalable_table(uint32_t dest_ip, void *table);

//Custom hash table functions
//custom/tightly integrated to scalable tables
//valid prefix_levevls are 1 to 32 inclusive
htable_t * htable_create (uint32_t prefix_level);
void htable_delete(htable_t * htable);
void htable_delete_llist(bucket_t * bucket);//delete collision resolution llist at an index in bucket ptr array
//prefix must match format for corresponding prefix level
void htable_insert(htable_t * htable, bucket_type_t btype, uint32_t prefix, uint32_t nxt_hop_addr, uint32_t rope);//prefix must be masked according to level already
bucket_t * htable_insert_llist(bucket_t * bucket_ll, bucket_t * n_bucket, htable_t * htable);//linked list insert for collision resolution0
//key is prefix, masked to length of corresponding prefix level
//returns index into hast table
uint32_t htable_hash(htable_t * htable, uint32_t key);
//uses index to search entry or linked list at index for prefix
bucket_t * htable_search(htable_t * htable, uint32_t prefix);
bucket_t * htable_search_llist(bucket_t * bucket, uint32_t prefix);//index=htable_hash(prefix), bucket_t*=htable[prefixlevel]->buckets[]

//*****FUTURE UPGRADE*****
//htable_t* htable_resize(htable_t * htable);//doubles the size of buckets, copies old bucket entries into correct new buckets, deletes old buckets
//currently working off MAX_BUCKETS during/from initialization/htable_creat()
//not bad for power of 2 nature of scalable tables, max unique entries are 2^prefix_level
//hashtable memory usage alleviated since moving to array of pointers to buckets,
//unused buckets only occupy a NULL pointer instead of the entire bucket_t struct

#endif