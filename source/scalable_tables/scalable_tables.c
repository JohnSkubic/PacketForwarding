/*
 *
 *  Created By: Nick Pfister
 *
 *  Description:
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "utility.h"
#include "scalable_tables.h"
//#include "np_hashtables.h"

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
  //*****small_table_t *s_table = NULL;
  //if((*****s_table = *****build_small_table(table, num_entries)) == NULL) {
    //printf("Error: Could not build scalable table\n");
    //return EXIT_FAILURE;
  //}
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

trie_node_t * build_trie_table(route_table_entry_t * table, int num_entries){
	uint32_t i;
	trie_node_t * trie;
	trie = NULL;

	for(i=0;i<num_entries;i++){
		trie = insert_trie_node(trie,&table[i],0);
	}

	return trie;
}

//p (char*)inet_ntoa(htonl(table[$table_ptr++].dest_addr.address)) -- useful gdb to visualize IP addresses
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