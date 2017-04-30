/*
 *
 *  Created By: Nick Pfister
 *
 *  Description: "Scalable High Speed Routing Lookups"
 *               part of implementation of http://conferences.sigcomm.org/sigcomm/1997/papers/p182.pdf
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "scalable_tables.h"

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
  // 1st pass -- trie
  trie_node_t * trie;
  if((trie = build_trie_table(table, num_entries)) == NULL) {
    printf("Error: Could not build trie\n");
    return EXIT_FAILURE;
  }

  // 2nd pass -- scalable table = ropes and hash tables
  htable_t ** scalable_table = NULL;
  if((scalable_table = build_scalable_table(table, num_entries)) == NULL) {
    printf("Error: Could not build scalable table\n");
    return EXIT_FAILURE;
  }
  //no longer need "1st pass trie" after scalable table is built
  destroy_trie_table(trie);

  // Run test (fourth argument is function pointer to lookup function)
  printf("Testing scalable tables\n");
  //test_routing_table(trace, num_tests, (void*)*****s_table, *****lookup_small_table);

  /* Free Resources */
  destroy_routing_table(table);
  destroy_routing_table(trace);
  //*****destroy_scalable_table(*****s_table);

  return EXIT_SUCCESS;
}

// ********** BEGIN SCALABLE FUNCTIONS **********

htable_t ** build_scalable_table(route_table_entry_t * table, int num_entries){
	htable_t ** scalable_htables;
	//rope_t * initial_rope;

	scalable_htables = init_scalable_htables((uint32_t)32);//init array of hash table pointers, IPv4 w/ notions to expandability to IPv6

	// **** HASH TABLES TESTING ****
	bucket_t * testbucket;
	uint32_t i;
	for(i=0;i<32;i += 1){
		// small hash table test of initial operability
		printf("creating ");
		scalable_htables[i]=htable_create(i+1);
		printf("done and ");
		htable_insert(scalable_htables[i],both_t,0xaabbffff,0x10101010,0xf9f9f9f9,NULL);
		htable_insert(scalable_htables[i],both_t,0xffffffff,0x10101010,0xf9f9f9f9,NULL);
		htable_insert(scalable_htables[i],both_t,0xffffefff,0x10101010,0xf9f9f9f9,NULL);
		htable_insert(scalable_htables[i],both_t,0xfeffffff,0x10101010,0xf9f9f9f9,NULL);
		printf("inserted at level: %d\n", i+1);

		//test search
		printf("searching:\n");
		testbucket = htable_search(scalable_htables[i],(0xaabbaabb));
		if(testbucket)/*not null*/printf("prefix found: %x\n", testbucket->prefix);
		testbucket = htable_search(scalable_htables[i],(0xffffffff));
		if(testbucket)/*not null*/printf("prefix found: %x\n", testbucket->prefix);
		testbucket = htable_search(scalable_htables[i],(0xfeffffff));
		if(testbucket)/*not null*/printf("prefix found: %x\n", testbucket->prefix);
		testbucket = htable_search(scalable_htables[i],(0xffffefff));
		if(testbucket)/*not null*/printf("prefix found: %x\n", testbucket->prefix);
	}

	//figure out core dump, get correct print, DONE
	//write a delete scalable tables or htables, or both one call other, to test deletions
	//write overall scalable table data structure

	//LOTS OF OTHER STUFF

	//return value SHOULD BECOME THE YET TO BE CREATED OVERALL SCALABLE
	//TABLE STRUCT WITH ROPES(at least the initial one, possibly array or
	// ropes where id's are only thing stored in hash tables)
	return scalable_htables;
}

htable_t ** init_scalable_htables(uint32_t num_levels){
	htable_t ** scalable_htables;
	scalable_htables = malloc(num_levels*sizeof(htable_t *));

	return scalable_htables;
}

void destroy_rope(rope_t * rope){
	if(rope == NULL){return;}//done
	destroy_rope(rope->nxt_rope_node);//walk llist
	free(rope);//free this rope node
	return;
}

// ********** END SCALABLE FUNCTIONS **********

// ********** BEGIN HASHTABLE FUNCTIONS **********

//valid prefix_levels 1 to 32 inclusive 
htable_t * htable_create(uint32_t prefix_level){
	htable_t * htable;
	uint32_t orig_num_buckets,num_buckets,i;
	uint32_t temp_key,shamt,shamt_mask,level_mask;

	orig_num_buckets = (prefix_level==32) ? 0x80000000 : (1 << prefix_level);//2 to power --> prefix_level
	num_buckets = ( orig_num_buckets < MAX_BUCKETS) ? orig_num_buckets : MAX_BUCKETS ;//handles 0 returned by 2^32 if MAX_BUCKETS is that big

	//for hash function, shamt would otherwise need to be computed on each call
	//compute once on creation, not per call to htable_hash()
	shamt_mask = 0;
	temp_key = num_buckets;//num_buckets is always a power of 2 (requirement)
	while(temp_key >>= 1) ++shamt_mask;//shamt=log2(num_buckets),2^shamt=num_buckets
	shamt = 32 - shamt_mask;//prefix lookups implies interest in MSB bits

	level_mask =0;
	temp_key = orig_num_buckets;//to mask for actual number of level (supports when fewer buckets than 2^level)
	while(temp_key >>= 1) ++level_mask;

	//initialize hash table
	htable = malloc(sizeof(htable_t));
	htable->level = prefix_level;
	htable->num_buckets = num_buckets;
	htable->shamt = shamt;//used by hash function
	htable->mask = (shamt_mask == 0) ? 0x00000000 : (0xFFFFFFFF << (32-shamt_mask));//used for inserting at correct prefix
	htable->lmask = (level_mask == 0) ? 0x00000000 : (0xFFFFFFFF << (32-level_mask));//used for inserting/searching prefix
	htable->num_entries = 0;
	htable->num_collisions = 0;
	htable->buckets = malloc(num_buckets*sizeof(bucket_t*));//moved to array of pointers to buckets, ptrs only populated if index used

	//ptrs only populated if index used
	for(i=0;i < num_buckets ;i++){
		htable->buckets[i] = NULL;
	}

	return htable;
}

bucket_t * htable_search(htable_t * htable, uint32_t prefix){//search for prefix in hash table
	return htable_search_llist(htable->buckets[htable_hash(htable, prefix)],(prefix& htable->lmask));
                                             //^every search need not remember to call hash()
}
bucket_t * htable_search_llist(bucket_t * bucket, uint32_t prefix){
	// expects prefix to be masked off corresponding to hash table's level (or precomputed level mask)
	if(bucket == NULL) return bucket; //return of null means not found/present
	if(bucket->prefix == prefix) return bucket;//return found matching bucket
	return htable_search_llist(bucket->nxt_bucket, prefix);//continue to search in collision resolved linked list
}

uint32_t htable_hash(htable_t * htable, uint32_t key){//uses log2(num_buckets) MSB bits as index into buckets **
	return (key >> htable->shamt);//made possible by "pre"-calculation on htable creation
}

void htable_insert(htable_t * htable, bucket_type_t btype, uint32_t prefix, uint32_t bmp, uint32_t nxt_hop_addr, rope_t * rope){//remember to have already and-ed with mask provided in hash table struct
	//overwrites duplicates -- existing matching prefix entries
	uint32_t ht_index;
	ht_index = htable_hash(htable, prefix);

	//malloc and assemble new bucket_t
	bucket_t * n_bucket;
	n_bucket = malloc(sizeof(bucket_t));
	n_bucket->bucket_type = btype;
	n_bucket->prefix = prefix & htable->lmask;
	n_bucket->bmp = bmp;
	n_bucket->nxt_hop_addr = nxt_hop_addr;
	n_bucket->new_rope = rope;

	//increment entries in this hash table
	//to handle duplicates (marker, prefix to both) htable_insert_llist will decrement
	htable->num_entries++;

	//bucket does not exist at this ht_index yet
	//htable_insert_llist will increment, because it will appear as null, counteract this
	if(htable->buckets[ht_index] == NULL){	htable->num_collisions--; }

	//insert into hash table
	//resolve collisions, should they exist
	htable->buckets[ht_index] = htable_insert_llist(htable->buckets[ht_index], n_bucket, htable);
}
bucket_t * htable_insert_llist(bucket_t * bucket_ll, bucket_t * n_bucket, htable_t * htable){
	//insert at end of list, order doesn't matter as lookups are random :(

	//new insertion
	if(bucket_ll == NULL){
		//inserting means collision
		//except for 1st insert, which is accounted for by caller
		htable->num_collisions++;
		
		return n_bucket;		
	}
	else if (bucket_ll->prefix == n_bucket->prefix){//prefix matches --> duplicate (usually a modify)
		//modify --> (marker,prefix to both)
		n_bucket->nxt_bucket = bucket_ll->nxt_bucket;
		free(bucket_ll);//simply replace, and free
		htable->num_entries--;//avoid double counting entries
		
		return n_bucket;
	}
	else //walk llist
		bucket_ll->nxt_bucket = htable_insert_llist(bucket_ll->nxt_bucket, n_bucket, htable);
	return bucket_ll;
}

void htable_delete(htable_t * htable){
	uint32_t i;
	//free any existing buckets and possibly,
	//associated llists due to collision resolution
	for(i=0; i < (htable->num_entries); i++){
		htable_delete_llist(htable->buckets[i]);
	}
	//free array of bucket pointers
	free(htable->buckets);
	//free htable
	free(htable);
	return;
}
void htable_delete_llist(bucket_t * bucket_ll){
	if(bucket_ll == NULL) { return; }// at end of list
	destroy_rope(bucket_ll->new_rope);//free rope if exists
	htable_delete_llist(bucket_ll->nxt_bucket);//walk llist
	free(bucket_ll);//free this node
	return;
}

// ********** END HASHTABLE FUNCTIONS **********

// ********** BEGIN TRIE FUNCTIONS **********

trie_node_t * build_trie_table(route_table_entry_t * table, int num_entries){
	uint32_t i;
	trie_node_t * trie;
	trie = NULL;

	for(i=0;i<num_entries;i++){
		trie = insert_trie_node(trie,&table[i],0);
	}

	return trie;
}

//p (char*)inet_ntoa(htonl(table[$table_ptr++].dest_addr.address)) -- useful gdb command to visualize IP addresses
trie_node_t * insert_trie_node(trie_node_t * trie, route_table_entry_t * table_entry, uint32_t curr_level) {

	if(trie == NULL){//current node does not exist
		//allocate trie_node_t
		trie = malloc(sizeof(trie_node_t));
		//initialize
		trie->real_prefix=0;//FALSE
		trie->n_prefix_below = 0;
		trie->prefix_len_below = NULL;
		trie->mask = (curr_level == 0) ? 0x00000000 : (0xFFFFFFFF << (32-curr_level));//need to be able to shift uint32_t by 32, C/x86 do not support 32 bit shift, only 0-31 bit shift
		trie->prefix = (table_entry->dest_addr.address & trie->mask);
		trie->prefixlen = curr_level;//level this node lives at
		trie->nxt_hop_addr = 0;
		
		trie->left = NULL;
		trie->right= NULL;
	}//my level, insert prefix and mask already taken care of on first initialization

	if(curr_level != table_entry->dest_addr.mask){//not my level, go to longer prefix length
		//update curr_node accordingly
		//store unique prefix length that will be stored below this trie node
		//increment number of prefix lengths stored below this trie node, if unique
		uint32_t duplicate,goleftmask;
		duplicate = 0;//FALSE
		trie->prefix_len_below = insert_prefix_len_below(trie->prefix_len_below,table_entry,&duplicate);
		if(!duplicate){
			trie->n_prefix_below++;
		}
		//go to next level
		//choose direction to go
		//next bit is next LSB
		goleftmask = ~((trie->mask) | ((~trie->mask) >> 1));
		//ex, curr_level=2, mask = 0xFFFFFFFC
		//ex, goleft mask = ~(0xFFFFFFFC | 0x00000001) = ~(0xFFFFFFFD)
		//ex, goleft mask = 0x00000002
		//ex, extracts whether next bit is 1 (!=0) or 0 (=0)
		if( (table_entry->dest_addr.address & goleftmask) != 0 ){
			//go left (next LSB bit is 1)
			trie->left  = insert_trie_node(trie->left ,table_entry,++curr_level);
		}
		else{//go right (next LSB bit is 0)
			trie->right = insert_trie_node(trie->right,table_entry,++curr_level);
		}
	}
	else{//my level, mark as real prefix node (not marker)
		trie->real_prefix = 1;//TRUE
		trie->nxt_hop_addr = table_entry->next_hop_addr;
	}

	return trie;
}

prefix_len_below_t * insert_prefix_len_below(prefix_len_below_t * prefix_len_below, route_table_entry_t * table_entry,uint32_t * duplicate){
	//linked list insert of prefix lengths below trie node
	

	// < less than
	//prefix len is not in list already and is smaller than all previous entries
	if(prefix_len_below == NULL){
		prefix_len_below = malloc(sizeof(prefix_len_below_t));
		prefix_len_below->next_prefix_len_below = NULL;
		prefix_len_below->prefix_len = table_entry->dest_addr.mask;//
		return prefix_len_below;//done
	}

	// = equal
	//does not insert a duplicate prefix len below
	if(prefix_len_below->prefix_len == table_entry->dest_addr.mask){
		*duplicate = 1;//TRUE//signal to not increment counter on duplicate (n_prefix_below)
		return prefix_len_below;// no need to go further down the list
	}

	// > greater than current linked list node
	// insert into the middle of list
	if(table_entry->dest_addr.mask > prefix_len_below->prefix_len){
		prefix_len_below_t * temp;
		temp = malloc(sizeof(prefix_len_below_t));
		temp->next_prefix_len_below = prefix_len_below;
		temp->prefix_len = table_entry->dest_addr.mask;

		return temp;//done
	}

	// walk down tree
	// if here, prefix len to be inserted is smaller than current node of linked list
	prefix_len_below->next_prefix_len_below = insert_prefix_len_below(prefix_len_below->next_prefix_len_below,table_entry,duplicate);

	return prefix_len_below;
}

void destroy_trie_table(trie_node_t * trie){
	if(trie == NULL){
		return;
	}
	//post order traversal
	destroy_trie_table(trie->left );
	destroy_trie_table(trie->right);

	destroy_prefix_len_below(trie->prefix_len_below);
	free(trie);
	return;
}

void destroy_prefix_len_below(prefix_len_below_t * prefix_len_below){
	//destroy linked list of prefixes stored at each trie node
	if(prefix_len_below == NULL){
		return;//end of list
	}
	destroy_prefix_len_below(prefix_len_below->next_prefix_len_below);

	free(prefix_len_below);
	return;
}

// ********** END TRIE FUNCTIONS **********


