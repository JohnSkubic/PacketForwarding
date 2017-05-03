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
  int default_entry_nxt_hop;
  if((trie = build_trie_table(table, num_entries, &default_entry_nxt_hop)) == NULL) {
    printf("Error: Could not build trie\n");
    return EXIT_FAILURE;
  }

  // 2nd pass -- scalable table = ropes and hash tables
  scalable_table_t * scalable_table = NULL;
  if((scalable_table = build_scalable_table(trie, num_entries)) == NULL) {
    printf("Error: Could not build scalable table\n");
    return EXIT_FAILURE;
  }
  scalable_table->default_entry_nxt_hop = default_entry_nxt_hop;
  printf("DEFAULT ENTRY nxthop: %x\n", default_entry_nxt_hop);
  //no longer need "1st pass trie" after scalable table is built
  destroy_trie_table(trie);

  // Run test (fourth argument is function pointer to lookup function)
  //*****printf("Testing scalable tables\n");
  test_routing_table(trace, num_tests, (void*) scalable_table, lookup_scalable_table);

  /* Free Resources */
  destroy_routing_table(table);
  destroy_routing_table(trace);
  destroy_scalable_table(scalable_table);

  return EXIT_SUCCESS;
}

// ********** BEGIN SCALABLE FUNCTIONS **********

scalable_table_t * build_scalable_table(trie_node_t * trie, int num_entries){//convert trie into scalable table (2nd pass)
	scalable_table_t * scalable_table;
	scalable_table = malloc(sizeof(scalable_table_t *));
	scalable_table->init_rope = 0x0000808B;//level 16,8,4,2,1 search order
	uint32_t i;

	//create array of hashtables
	scalable_table->scalable_htables = init_scalable_htables((uint32_t)32);//init array of hash table pointers, IPv4 w/ notions to expandability to IPv6

	//walk trie, insert into scalable table
	//note: init_rope 16,8,4,2,1
	//Level 1
	//printf("LEVEL: %d\n", 1);
	scalable_table->scalable_htables[0]=htable_create(1);
	trie_level_read_scalable_insert(trie,1,scalable_table->scalable_htables,1);
	//Level 2-3
	for(i=2;i<=3;i++){
		//printf("LEVEL: %d\n", i);
		//okay to init all htables, this is for a core router, will have 10k+ entries, all htables bound to have entries
		scalable_table->scalable_htables[i-1]=htable_create(i);//levels are 1 indexed, array of htables is 0 indexed (1 to 32 length prefixes, 0 length is the default address)
		//insert "i's" level of trie nodes into hashtables (scalable table)
		trie_level_read_scalable_insert(trie,i,scalable_table->scalable_htables,3);//3 max depth for 2 (initrope)
	}
	//Level 4-7
	for(i=4;i<=7;i++){
		//printf("LEVEL: %d\n", i);
		//okay to init all htables, this is for a core router, will have 10k+ entries, all htables bound to have entries
		scalable_table->scalable_htables[i-1]=htable_create(i);//levels are 1 indexed, array of htables is 0 indexed (1 to 32 length prefixes, 0 length is the default address)
		//insert "i's" level of trie nodes into hashtables (scalable table)
		trie_level_read_scalable_insert(trie,i,scalable_table->scalable_htables,7);//7 max depth for 4 (initrope)
	}
	//Level 8-15
	for(i=8;i<=15;i++){
		//printf("LEVEL: %d\n", i);
		//okay to init all htables, this is for a core router, will have 10k+ entries, all htables bound to have entries
		scalable_table->scalable_htables[i-1]=htable_create(i);//levels are 1 indexed, array of htables is 0 indexed (1 to 32 length prefixes, 0 length is the default address)
		//insert "i's" level of trie nodes into hashtables (scalable table)
		trie_level_read_scalable_insert(trie,i,scalable_table->scalable_htables,15);//15 max depth for 8 (initrope)
	}
	//Level 16-32
	for(i=16;i<=32;i++){
		//printf("LEVEL: %d\n", i);
		//okay to init all htables, this is for a core router, will have 10k+ entries, all htables bound to have entries
		scalable_table->scalable_htables[i-1]=htable_create(i);//levels are 1 indexed, array of htables is 0 indexed (1 to 32 length prefixes, 0 length is the default address)
		//insert "i's" level of trie nodes into hashtables (scalable table)
		trie_level_read_scalable_insert(trie,i,scalable_table->scalable_htables,32);//32 max depth for 16 (initrope)
	}

	// **** SCALABLE INSERT TESTING ****
	
	bucket_t * testbucket;
	for(i=0;i<32;i++){
		testbucket = htable_search(scalable_table->scalable_htables[i],(0x5aa30000));
		if(testbucket) printf("prefix found: %8x level: %2d type: %1d bmp: %8x nxt_hop: %4d rope: %8x lmask: %x\n", testbucket->prefix, (i+1), (uint32_t)testbucket->bucket_type,testbucket->bmp,testbucket->nxt_hop_addr,testbucket->new_rope,scalable_table->scalable_htables[i]->lmask);//not null
	}
	// **** END SCALABLE INSERT TESTING ****
	
	return scalable_table;
}

htable_t ** init_scalable_htables(uint32_t num_levels){
	htable_t ** scalable_htables;
	scalable_htables = malloc(num_levels*sizeof(htable_t *));

	return scalable_htables;
}

void destroy_scalable_table(scalable_table_t* scalable_table){
	uint32_t i;

	//destroy hashtables and contents
	for(i=0;i<32;i++){
		htable_delete(scalable_table->scalable_htables[i]);
	}
	//free array of hashtable pointers
	free(scalable_table->scalable_htables);
	free(scalable_table);
}

uint32_t prefix_len_below_to_rope(uint32_t prefix_len_below, uint32_t max_depth){//max depth will be 1,3,7,15,32
	if(prefix_len_below == 0){return 0;}//no need to calculate there is nothing below
	//erase all "prefix below me above max_depth"
	uint32_t erase_mask;
	erase_mask = ~((max_depth==32)?(0x00000000):(0xFFFFFFFF << max_depth));//ex. max depth =3 erase_mask = ~(FFFFFFFF << 3) = ~FFFFFFF8 = 00000007
	prefix_len_below &= erase_mask;//prefix_len_below now only contains binary search appropriate nodes below it

	//find median length to make right side of binary tree
	if(prefix_len_below == 0){return 0;}//no need to calculate there is nothing below
	uint32_t i,mask,lens_below,lens_in_rope;
	lens_below = 0;
	for(i=0;i<max_depth;i++){
		mask = level_to_mask(i+1);
		if(prefix_len_below & mask){//if something, then add discovered level to average
			lens_below++;
		}
	}
	lens_in_rope = lens_below/2;//right side of a bin tree
	if(lens_in_rope==0){//will never get this far if there are truly no lens below me even after erase_mask
		return prefix_len_below;//only has one entry that is the rope
	}
	//find where the right side of the bin tree ends
	uint32_t lens_found;
	lens_found = 0;
	i=0;
	for(i=0;lens_found < lens_in_rope;i++){//final i value will be where right side of bin tree (rope) begins
		mask = level_to_mask(i+1);
		if(prefix_len_below & mask){
			lens_found++;
		}
	}
	//erase left side of bin tree to make rope
	erase_mask = ~(((i+1)==32)?(0x00000000):(0xFFFFFFFF << (i+1)));//left side erase mask
	prefix_len_below &= erase_mask;
	//now prefix_len_below is a rope which is the right side of a bin tree sub tree
	return prefix_len_below;
}

uint32_t lookup_scalable_table ( uint32_t dest_ip, void *table ){
	scalable_table_t * scalable_table;
	htable_t ** scalable_htables;
	uint32_t curr_rope;
	//uint32_t bmp;
	uint32_t nxt_hop_addr;
	//uint32_t tdest_ip;//temp/working dest_ip if have to extract first bits (htable_search) does this
	uint32_t i;//level searching
	bucket_t * bucket;

	//init
	scalable_table = (scalable_table_t *) table;
	scalable_htables = scalable_table->scalable_htables;
	curr_rope = scalable_table->init_rope;
	//bmp = 0x00000000;
	nxt_hop_addr = scalable_table->default_entry_nxt_hop;//if nothing found this is the nxt hop
	bucket = NULL;

	//scalable table search
	while(curr_rope){//rope has something to search
		//pull first curr_rope and store it in i
		i = nxt_search_level(&curr_rope);

		//extract first "level" bits of dest_ip
		//built into search function -- uses precomputed mask (more efficient)
		//tdest_ip = ((i==32)?(0xFFFFFFFF):(~(0xFFFFFFFF >> i))) & dest_ip;//if not build into search

		//search htable of i for (t)dest_ip
		bucket = htable_search(scalable_htables[i-1],dest_ip);
		if(bucket != NULL){//hit in htable
			//bmp = bucket->bmp; not needed in this implementation
			//best bmp and associated nxt_hop so far
			nxt_hop_addr = bucket->nxt_hop_addr;//what we really care about
			//get new rope, if there is one, else end of search
			curr_rope = bucket->new_rope;
		}
	}

	//return next hop
	return nxt_hop_addr;
}

uint32_t nxt_search_level(uint32_t * rope){
	//strip leading zero off, return its position as a level (i+1)
	uint32_t i,mask;
	for(i=32;i>0;i--){
		mask = level_to_mask(i);
		if(*rope & mask){//if something, then add discovered level to average
			//erase from rope for next iteration (so the next level to be searched can be found)
			*rope &= ~(mask);//
			//i is MSB level
			return i;
		}
	}
	//never used unless no levels found
	printf("ERROR: no nxt_search_level\n");
	return 0;
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

	level_mask=0;
	temp_key = orig_num_buckets;//to mask for actual number of level (supports when fewer buckets than 2^level)
	while(temp_key>>=1) ++level_mask;//fails for 32 --> 0x80000000
	/*
	for(level_mask=0; temp_key ;level_mask++){
		temp_key >>= 1;
	}*/

	//initialize hash table
	htable = malloc(sizeof(htable_t));
	htable->level = prefix_level;
	htable->num_buckets = num_buckets;
	htable->shamt = shamt;//used by hash function
	htable->mask = (shamt_mask == 0) ? 0x00000000 : (0xFFFFFFFF << (32-shamt_mask));//used for inserting at correct prefix
	htable->lmask = (level_mask == 0) ? 0x00000000 : (orig_num_buckets==0x80000000) ? (0xFFFFFFFF) : (0xFFFFFFFF << (32-level_mask));//used for inserting/searching prefix
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

void htable_insert(htable_t * htable, bucket_type_t btype, uint32_t prefix, uint32_t bmp, uint32_t nxt_hop_addr, uint32_t rope){//remember to have already and-ed with mask provided in hash table struct
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
	if(htable==NULL) return;//unused hashtable
	//free any existing buckets and possibly,
	//associated llists due to collision resolution
	for(i=0; i < (htable->num_buckets); i++){
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
	htable_delete_llist(bucket_ll->nxt_bucket);//walk llist
	free(bucket_ll);//free this node
	return;
}

// ********** END HASHTABLE FUNCTIONS **********

// ********** BEGIN TRIE FUNCTIONS **********

trie_node_t * build_trie_table(route_table_entry_t * table, int num_entries, int * default_entry_nxt_hop){
	uint32_t i;
	trie_node_t * trie;
	trie = NULL;

	for(i=0;i<num_entries;i++){
		if(table[i].dest_addr.address==0){
			//printf("FOUND DEFAULT ENTRY: %x\n", table[i].next_hop_addr);
			*default_entry_nxt_hop = table[i].next_hop_addr;
			continue;//no need to try to insert default
			//insert_trie_node can handle/won't fail, but also won't insert as there is no level for length 0
		}
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
		trie->prefix_len_below = 0x00000000;
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
		insert_prefix_len_below(&trie->prefix_len_below,table_entry,&duplicate);
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

void insert_prefix_len_below(uint32_t * prefix_len_below, route_table_entry_t * table_entry,uint32_t * duplicate){
	//linked list insert of prefix lengths below trie node
	
	uint32_t temp_prefix_len_below,mask;
	mask = level_to_mask(table_entry->dest_addr.mask);
	temp_prefix_len_below = (*prefix_len_below) & mask;//manipulate before overwriting value
	
	if(temp_prefix_len_below){//if there is something here, we are inserting a duplicate
		*duplicate = 1;
	}
	//insert into bit field of prefix lengths below
	*prefix_len_below |= mask;
}

uint32_t level_to_mask(uint32_t level){
	uint32_t mask;
	switch(level){//decimal to bit field representation
		case 1:
			mask = 0x00000001;
			break;
		case 2:
			mask = 0x00000002;
			break;
		case 3:
			mask = 0x00000004;
			break;
		case 4:
			mask = 0x00000008;
			break;
		case 5:
			mask = 0x00000010;
			break;
		case 6:
			mask = 0x00000020;
			break;
		case 7:
			mask = 0x00000040;
			break;
		case 8:
			mask = 0x00000080;
			break;
		case 9:
			mask = 0x00000100;
			break;
		case 10:
			mask = 0x00000200;
			break;
		case 11:
			mask = 0x00000400;
			break;
		case 12:
			mask = 0x00000800;
			break;
		case 13:
			mask = 0x00001000;
			break;
		case 14:
			mask = 0x00002000;
			break;
		case 15:
			mask = 0x00004000;
			break;
		case 16:
			mask = 0x00008000;
			break;
		case 17:
			mask = 0x00010000;
			break;
		case 18:
			mask = 0x00020000;
			break;
		case 19:
			mask = 0x00040000;
			break;
		case 20:
			mask = 0x00080000;
			break;
		case 21:
			mask = 0x00100000;
			break;
		case 22:
			mask = 0x00200000;
			break;
		case 23:
			mask = 0x00400000;
			break;
		case 24:
			mask = 0x00800000;
			break;
		case 25:
			mask = 0x01000000;
			break;
		case 26:
			mask = 0x02000000;
			break;
		case 27:
			mask = 0x04000000;
			break;
		case 28:
			mask = 0x08000000;
			break;
		case 29:
			mask = 0x10000000;
			break;
		case 30:
			mask = 0x20000000;
			break;
		case 31:
			mask = 0x40000000;
			break;
		case 32:
			mask = 0x80000000;
			break;
		default://zero or error (level greater than 32)
			mask = 0x00000000;
			break;
	}
	return mask;
}

void destroy_trie_table(trie_node_t * trie){
	if(trie == NULL){
		return;
	}
	//post order traversal
	destroy_trie_table(trie->left );
	destroy_trie_table(trie->right);

	free(trie);
	return;
}

//this part of the build algorithm is very poorly described by the paper -- acknowledge wasteful storage of markers at non-visited levels, however ropes are faithful to algorithm, so are bmps
void trie_level_read_scalable_insert(trie_node_t * trie, uint32_t prefixlevel, htable_t ** scalable_htables, uint32_t max_depth){
	if(trie==NULL) return;
	else if(trie->prefixlen == prefixlevel){//insert this node, part of level inserting on currently
		// htable_insert arguments to assemble:
		// bucket_type_t btype, uint32_t bmp, uint32_t nxt_hop_addr, uint32_t rope;
		
		//INITIALIZE
		bucket_type_t bucket_type;
		uint32_t bmp, nxt_hop_addr, rope;
		bucket_type = empty_t;
		bmp = 0;
		nxt_hop_addr = 0;
		rope = 0;	

		//ASSEMBLE
		//marker or real prefix with possibly better matches below (both_t), need a rope and bmp
		//    marker_t               both_t
		if( (!trie->real_prefix) || (trie->real_prefix && trie->n_prefix_below)){
			//need bmp
				//marker -- search up for one htables above for bmp (usually just the htable above my level)
				if(!trie->real_prefix){
					bucket_type = marker_t;
					if(prefixlevel!=1){//one doesn't have any shorter best matching prefix (1 literally is the shortest to go)
						bucket_t * bucket;
						bucket = htable_search(scalable_htables[prefixlevel-2],trie->prefix);//htable search previous layer, know that a marker or prefix will be there for me, b/c low to high prefix length insertion order;
						if(bucket){
							bmp = bucket->bmp;
							//so search fx can simply save as it goes
							nxt_hop_addr = bucket->nxt_hop_addr;
						} /*else { //no longer a fatal error
							//printf("FATAL ERROR NO BMP IN PREVIOUS LEVEL\n");
						}*/
					}
				}
				//real w/ possibly better matches below (both_t) -- bmp is my prefix (b/c i'm a real prefix)
				else{
					bucket_type = both_t;
					bmp = trie->prefix;
					nxt_hop_addr = trie->nxt_hop_addr;
				}
			//need rope -- max depth limits rope from pointing outside scope of subbinary tree we're in
			rope = prefix_len_below_to_rope(trie->prefix_len_below, max_depth);// not deriving max depth because cheaper to calc and pass in once, than calc for every entry in trie (ex 10k)
			
			//don't insert pure marker, if it points to something outside scope of binary tree currently in
			//known by rope not having anything in it, because prefix_len_below_to_rope filtered out pointers to levels higher than current subbintree scope
			if((bucket_type == marker_t) && (rope == 0x00000000)){
				return;
			}
		}
		//real prefix w/ NO possible better match (prefix_t)
		else{
			bucket_type = prefix_t;
			//bmp is myself
			bmp = trie->prefix;
			nxt_hop_addr = trie->nxt_hop_addr;
			//rope isn't needed
		}

		//INSERT
		htable_insert(scalable_htables[prefixlevel-1], bucket_type, trie->prefix, bmp, nxt_hop_addr, rope);

		//testing print
		//printf("prefix: %x, nb: %d, real: %d, lbelow: %x level: %d  nhop: %d\n", trie->prefix, trie->n_prefix_below,trie->real_prefix, trie->prefix_len_below, prefixlevel,trie->nxt_hop_addr);
		
		return;//not interested in anything below level being read at(this one), no further recursion
	}

	trie_level_read_scalable_insert(trie->left , prefixlevel, scalable_htables, max_depth);
	trie_level_read_scalable_insert(trie->right, prefixlevel, scalable_htables, max_depth);
}

// ********** END TRIE FUNCTIONS **********


