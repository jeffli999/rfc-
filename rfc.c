/***************************************
   chunk_id  chunk_size  header-field
       0         16       s.ip[15:0]
       1         16       s.ip[31:16]
       2         16       d.ip[15:0]
       3         16       d.ip[31:16]
       4         8        proto
       5         16       s.port
       6         16       d.port   
****************************************/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include "rfc.h"
#include "flow.h"

#define MIN(a, b)  (a) < (b) ? (a) : (b)
#define MAX(a, b)  (a) > (b) ? (a) : (b)

const int chunk_to_field[MAXCHUNKS] = {0, 0, 1, 1, 2, 3, 4};
const int shamt[MAXCHUNKS] = {0, 16, 0, 16, 0, 0, 0};

extern flow_entry_t *flows;
extern int	    num_flows;	// current number of flows
extern int	    *rule_types[FIELDS];

FILE	    *fpr;	// ruleset file
FILE	    *fpt;	// test packet trace file

uint16_t    numrules;	// actual number of rules in rule set
pc_rule_t   *ruleset;	// the rule set for packet classification

// functions to be performed by this program, which are specified in command-line parameters
int		func_write_flow, func_read_flow, func_check_classify;

// end points for each chunk in phase 0, used for generating CBMs in phase 0
int		epoints[MAXCHUNKS][MAXRULES*2+2];
int		num_epoints[MAXCHUNKS];

// CBMs for each chunk at each phase: each CBM consists of major part and minor part
cbm_t		*phase_cbms[PHASES][MAXCHUNKS];
int		num_cbms[PHASES][MAXCHUNKS];
int		cbm_sizes[PHASES][MAXCHUNKS];

// phase tables containing CBM ids for each chunk at each phase
int		*phase_tables[PHASES][MAXCHUNKS];
int		phase_table_sizes[PHASES][MAXCHUNKS];

// each table[phase][chunk][0] is for crossproduct table before cbm shuffling, and
// each table[phase][chunk][1] is for crossproduct table after cbm shuffling
block_entry_t	*block_id_tables[PHASES][MAXCHUNKS];
int		block_table_sizes[PHASES][MAXCHUNKS];
point_block_t	*point_block_tables[PHASES][MAXCHUNKS];
int		point_table_sizes[PHASES][MAXCHUNKS];
array_block_t	*row_block_tables[PHASES][MAXCHUNKS];
int		row_table_sizes[PHASES][MAXCHUNKS];
array_block_t	*col_block_tables[PHASES][MAXCHUNKS];
int		col_table_sizes[PHASES][MAXCHUNKS];
matrix_block_t	*matrix_block_tables[PHASES][MAXCHUNKS];
int		matrix_table_sizes[PHASES][MAXCHUNKS];

int		rules_len_count[MAXRULES+1];

// cbm_lookup() works slow when there is a large number of CBMs,
// To speed up, we can limit its search to CBMs with the same rulesum
// A hash table hashing on CBM's rulesum is introduced for this purpose
// Alert: no less than 65536, otherwise phase 0 full cbm formulation will go wrong!
#define HASH_TAB_SIZE   99787
int     *cbm_hash[HASH_TAB_SIZE];
int     cbm_hash_size[HASH_TAB_SIZE];   
int     cbm_hash_num[HASH_TAB_SIZE];    

// data structures for examining the two bottleneck functions, cmb_lookup(), cbm_intersect()
long	hash_stats[10000];
long	intersect_stats[MAXRULES*2];



int ilog2(unsigned int v)
{
    int	    i = 0;
    while (v >>= 1) i++;
    return i;
}



//--------------------------------------------------------------------------------------------------
//
// Section preprocessing: functions before RFC construction
//
//--------------------------------------------------------------------------------------------------


void parseargs(int argc, char *argv[]) 
{
    int	c;
    int ok = 1;

    while ((c = getopt(argc, argv, "r:t:w:h")) != -1) {
	switch (c) {
	    case 'w':
		fpt = fopen(optarg, "w");
		func_write_flow = 1;
		break;
	    case 'r':
		fpr = fopen(optarg, "r");
		break;
	    case 't':
		fpt = fopen(optarg, "r");
		func_read_flow = 1;
		break;
	    case 'h':
		printf("rfc [-w trace-to-write][-r ruleset][-t trace-to-read][-h]\n");
		exit(1);
		break;
	    default:
		ok = 0;
	}
    }

    if(fpr == NULL) {
	printf("can't open ruleset file\n");
	ok = 0;
    }
    if((fpt == NULL) && (func_write_flow || func_read_flow)){
	printf("can't open flow trace file\n");
	ok = 0;
    }
    if (!ok || optind < argc) {
	fprintf(stderr, "rfc [-w trace-to-write][-r ruleset][-t trace-to-read][-h]\n");
	exit(1);
    }
}


int loadrule(FILE *fp, pc_rule_t *rule){

    int tmp;
    unsigned sip1, sip2, sip3, sip4, siplen;
    unsigned dip1, dip2, dip3, dip4, diplen;
    unsigned proto, protomask;
    int i = 0;

    while(1) {
	if(fscanf(fp,"@%d.%d.%d.%d/%d %d.%d.%d.%d/%d %d : %d %d : %d %x/%x\n", 
		    &sip1, &sip2, &sip3, &sip4, &siplen, &dip1, &dip2, &dip3, &dip4, &diplen, 
		    &ruleset[i].field[3].low, &ruleset[i].field[3].high, &ruleset[i].field[4].low, &ruleset[i].field[4].high,
		    &proto, &protomask) != 16) break;
	if(siplen == 0) {
	    ruleset[i].field[0].low = 0;
	    ruleset[i].field[0].high = 0xFFFFFFFF;
	} else if(siplen > 0 && siplen <= 8) {
	    tmp = sip1<<24;
	    ruleset[i].field[0].low = tmp;
	    ruleset[i].field[0].high = ruleset[i].field[0].low + (1<<(32-siplen)) - 1;
	}else if(siplen > 8 && siplen <= 16) {
	    tmp = sip1<<24; tmp += sip2<<16;
	    ruleset[i].field[0].low = tmp; 	
	    ruleset[i].field[0].high = ruleset[i].field[0].low + (1<<(32-siplen)) - 1;	
	}else if(siplen > 16 && siplen <= 24) {
	    tmp = sip1<<24; tmp += sip2<<16; tmp +=sip3<<8; 
	    ruleset[i].field[0].low = tmp; 	
	    ruleset[i].field[0].high = ruleset[i].field[0].low + (1<<(32-siplen)) - 1;			
	}else if(siplen > 24 && siplen <= 32) {
	    tmp = sip1<<24; tmp += sip2<<16; tmp += sip3<<8; tmp += sip4;
	    ruleset[i].field[0].low = tmp; 
	    ruleset[i].field[0].high = ruleset[i].field[0].low + (1<<(32-siplen)) - 1;	
	}else {
	    printf("Src IP length exceeds 32\n");
	    return 0;
	}

	if(diplen == 0) {
	    ruleset[i].field[1].low = 0;
	    ruleset[i].field[1].high = 0xFFFFFFFF;
	}else if(diplen > 0 && diplen <= 8) {
	    tmp = dip1<<24;
	    ruleset[i].field[1].low = tmp;
	    ruleset[i].field[1].high = ruleset[i].field[1].low + (1<<(32-diplen)) - 1;
	}else if(diplen > 8 && diplen <= 16) {
	    tmp = dip1<<24; tmp +=dip2<<16;
	    ruleset[i].field[1].low = tmp; 	
	    ruleset[i].field[1].high = ruleset[i].field[1].low + (1<<(32-diplen)) - 1;	
	}else if(diplen > 16 && diplen <= 24) {
	    tmp = dip1<<24; tmp +=dip2<<16; tmp+=dip3<<8;
	    ruleset[i].field[1].low = tmp; 	
	    ruleset[i].field[1].high = ruleset[i].field[1].low + (1<<(32-diplen)) - 1;			
	}else if(diplen > 24 && diplen <= 32) {
	    tmp = dip1<<24; tmp +=dip2<<16; tmp+=dip3<<8; tmp +=dip4;
	    ruleset[i].field[1].low = tmp; 	
	    ruleset[i].field[1].high = ruleset[i].field[1].low + (1<<(32-diplen)) - 1;	
	}else {
	    printf("Dest IP length exceeds 32\n");
	    return 0;
	}

	if(protomask == 0xFF) {
	    ruleset[i].field[2].low = proto;
	    ruleset[i].field[2].high = proto;
	} else if(protomask == 0) {
	    ruleset[i].field[2].low = 0;
	    ruleset[i].field[2].high = 0xFF;
	} else {
	    printf("Protocol mask error\n");
	    return 0;
	}
	i++;
    }

  return i;
}



//--------------------------------------------------------------------------------------------------
//
// Section end-point: end-point processing functions
//
//--------------------------------------------------------------------------------------------------


static int point_cmp(const void *p, const void *q)
{
    return *(int *)p - *(int *)q;
}


int sort_endpoints()
{
    int	    chunk, i;

    for (chunk = 0; chunk < MAXCHUNKS; chunk++) {
	qsort(epoints[chunk], numrules*2+2, sizeof(int), point_cmp);
	// remove redundant end points for multiple rules having the same end points
	for (i = 0, num_epoints[chunk] = 1; i < numrules*2+2; i++) {
	    if (epoints[chunk][i] != epoints[chunk][num_epoints[chunk]-1])
		epoints[chunk][num_epoints[chunk]++] = epoints[chunk][i];
	}
    }
}


// the first step for rfc is to generate end points on each field chunk
int gen_endpoints()
{
    int	    i, f, k, chunk;
    
    for (chunk = 0; chunk < MAXCHUNKS; chunk++) {
	f = chunk_to_field[chunk];
	k = shamt[chunk];
	epoints[chunk][0] = 0;
	for (i = 0; i < numrules; i++) {
	    epoints[chunk][2*i+1] = (ruleset[i].field[f].low >> k) & 0xFFFF;
	    epoints[chunk][2*i+2] = (ruleset[i].field[f].high >> k) & 0xFFFF;
	}
	epoints[chunk][2*i+1] = 65535;
    }

    sort_endpoints();
}


int dump_endpoints()
{
    int     chunk, i;
    for (chunk = 0; chunk < MAXCHUNKS; chunk++) {
	printf("end_points[%d]: %d\n", chunk, num_epoints[chunk]);
	//
	//for (i = 0; i < num_epoints[chunk]; i++)
	//   printf("%d: %d  ", i, epoints[chunk][i]);
    }
    printf("\n");

}



//--------------------------------------------------------------------------------------------------
//
// Section CBM: CBM processing functions
//
//--------------------------------------------------------------------------------------------------


void init_cbm_hash()
{
    int	i;

    for (i = 0; i < HASH_TAB_SIZE; i++) {
        cbm_hash[i] = (int *) malloc(2*sizeof(int));
        cbm_hash_size[i] = 2;
        cbm_hash_num[i] = 0;
    }
}


void free_cbm_hash()
{
    int i;

    for (i = 0; i < HASH_TAB_SIZE; i++)
        free(cbm_hash[i]);
}


// a new CBM is added into the hash table to prevent duplicate CBMs added into the CBM set in the future
void add_to_hash(cbm_t *cbm)
{
    int	    h = cbm->rulesum % HASH_TAB_SIZE;
    
    cbm_hash[h][cbm_hash_num[h]] = cbm->id;
    if (++cbm_hash_num[h] == cbm_hash_size[h]) {
	cbm_hash_size[h] <<= 1;
	cbm_hash[h] = (int *) realloc(cbm_hash[h], cbm_hash_size[h]*sizeof(int));
    }
}


// check whether two rulelists are the same
int compare_rules(uint16_t *rules1, uint16_t *rules2, uint16_t n)
{
    int	    i;

    for (i = 0; i < n; i++) {
	if (rules1[i] != rules2[i])
	    return 0;
    }
    return  1;
}


// given a rulelist, check whether it is already in the given set of CBMs,
// return the hit CBM id if there is a match, otherwise return -1
int cbm_lookup(uint16_t *rules, uint16_t nrules, int rulesum, cbm_t *cbm_set)
{
    int	    h, i, n, id, match = 0;

    h = rulesum % HASH_TAB_SIZE;
    for (i = 0; i < cbm_hash_num[h]; i++) {
	id = cbm_hash[h][i];
	if (cbm_set[id].nrules != nrules)
	    continue;
	if (memcmp(rules, cbm_set[id].rules, nrules*sizeof(uint16_t)) == 0) {
	    hash_stats[i+1]++;
	    return id;
	}
    }
    hash_stats[i]++;
    return -1;
}


int cbm_rule_search(uint16_t rule, cbm_t *cbms, int ncbm)
{
    int		i,  j;

    for (i = 0; i < ncbm; i++) {
	for (j = 0; j < cbms[i].nrules; j++) {
	    if (cbms[i].rules[j] == rule) {
		printf("rule[%d] in cbm[%d]\n", rule, i);
		break;
	    } else if (cbms[i].rules[j] > rule)
		break;
	}
    }
}


// if the rulelist is not in the CBM set of current <phase, chunk>, create a new CBM with this rulelist,
// and add it into the CBM set of current < phase, chunk> (i.e., phase_cbms[phase][chunk])
int new_cbm(int phase, int chunk, uint16_t *rules, uint16_t nrules, int rulesum)
{
    static int	cbm_sizes[PHASES][MAXCHUNKS];
    int		cbm_id;
    cbm_t	*cbms;

    if (num_cbms[phase][chunk] == cbm_sizes[phase][chunk]) {
	cbm_sizes[phase][chunk] += 64;
	phase_cbms[phase][chunk] = realloc(phase_cbms[phase][chunk], cbm_sizes[phase][chunk]*sizeof(cbm_t));
    }
    cbms = phase_cbms[phase][chunk];
    cbm_id = num_cbms[phase][chunk];
    cbms[cbm_id].id = cbm_id;
    cbms[cbm_id].rulesum = rulesum;
    cbms[cbm_id].run = 0;
    cbms[cbm_id].nrules = nrules;
    cbms[cbm_id].rules = (uint16_t *) malloc(nrules*sizeof(uint16_t));
    memcpy(cbms[cbm_id].rules, rules, nrules*sizeof(uint16_t));
    num_cbms[phase][chunk]++;

    add_to_hash(&cbms[cbm_id]);
    rules_len_count[nrules]++;

    return cbm_id;
}


// just free its rule list to reclaim memory
void del_cbm(cbm_t *cbm)
{
    if (cbm->nrules > 0)
	free(cbm->rules);
}



// -------------------------------------------------------------------------------------------------
//
// Section blocking: functions for implementing blocking scheme for phase table space reduction.
//
// -------------------------------------------------------------------------------------------------


// for block type statistics on the original phase table scheme
/*
void table_block_stats(int *table, int n1, int n2)
{
    int	    nb1, nb2, type, i, j, type_counts[4];

    for (i = 0; i < 4; i++) 
	type_counts[i] = 0;

    nb1 = n1 / BLOCKSIZE;
    if (n1 % BLOCKSIZE != 0) nb1++;
    nb2 = n2 / BLOCKSIZE;
    if (n2 % BLOCKSIZE != 0) nb2++;

    printf("Table block stats\n");
    for (i = 0; i < nb1; i++) {
	for (j = 0; j < nb2; j++) {
	    type = get_block_type(table, i, j, n1, n2);
	    type_counts[type]++;
	}
    }

    for (i = 0; i < 4; i++)
	printf("type[%d]: %d\n", i, type_counts[i]);
}
*/


// dump out the rulelist of the CBM
void dump_cbm_rules(cbm_t *cbm)
{
    uint16_t	i;

    printf("cbm[%d]: ", cbm->id);
    for (i = 0; i < cbm->nrules; i++)
	printf("%u ", cbm->rules[i]);
    printf("\n");
}


// intersecting rulelists of two phase-1 CBMs
int cbm_intersect(int phase, int chunk, cbm_t *c1, cbm_t *c2, uint16_t *rules, int *rulesum)
{
    int		n = 0, ncmp = 0;
    uint16_t	i = 0, j = 0, rule;

    *rulesum = 0;
    while (i < c1->nrules && j < c2->nrules) {
	if (c1->rules[i] == c2->rules[j]) {
	    rule = c1->rules[i];
	    rules[n++] = rule;
	    *rulesum += rule;
	    if (phase == 3) // for the last phase, rules beyond the first one are meaningless
		break;
	    i++; j++;
	} else if (c1->rules[i] > c2->rules[j]) {
	    j++;
	} else {
	    i++;
	}
	ncmp++;
    }
    intersect_stats[ncmp]++;
    return n;
}


// construct CBM set for current <phase, chunk> by crossproducting two CBM sets from previous phase
void crossprod_2chunk(int phase, int chunk, cbm_t *cbms1, int n1, cbm_t *cbms2, int n2)
{
    int		i, j, cbm_id, cbm_id0, rulesum, cpd_size = n1 * n2;
    uint16_t	rules[MAXRULES], nrules;

    init_cbm_hash();

    phase_cbms[phase][chunk] = (cbm_t *) malloc(cpd_size*sizeof(cbm_t));
    for (i = 0; i < n1; i++) {
	if ((i & 0xFFF) == 0) // to show the progress for a long crossproducting process
	    fprintf(stderr, "crossprod_2chunk: %6d/%6d\n", i, n1);
	cbm_id0 = -1;
	for (j =  0; j < n2; j++) {
	    // 1. generate the intersect of two cbms from two chunks and trim it
	    nrules = cbm_intersect(phase, chunk, &cbms1[i], &cbms2[j], rules, &rulesum);
	    // 2. check whether the intersect cbm exists in crossproducted cbm list so far
	    cbm_id = cbm_lookup(rules, nrules, rulesum, phase_cbms[phase][chunk]);
	    if (cbm_id < 0) // 3. the intersect cbm is new, so add it to the crossproducted cbm list
		cbm_id = new_cbm(phase, chunk, rules, nrules, rulesum);
	    //4. fill the corresponding crossproduct table with the eqid (cmb_id)
	    phase_tables[phase][chunk][i*n2 + j] = cbm_id;
	    // 5. statistics on #runs in a row for deciding cbms1 shuffling
	    if (cbm_id != cbm_id0) {
		cbms1[i].run++;
		cbm_id0 = cbm_id;
	    }
	}
    }

    // statistics on #runs in a column for deciding cbms2 shuffling
    for (j = 0; j < n2; j++) {
	cbm_id0 = -1;
	for (i = 0; i < n1; i++) {
	    cbm_id = phase_tables[phase][chunk][i*n2 + j];
	    if (cbm_id != cbm_id0) {
		cbms2[j].run++;
		cbm_id0 = cbm_id;
	    }
	}
    }

    cpd_size = num_cbms[phase][chunk];
    phase_cbms[phase][chunk] = (cbm_t *) realloc(phase_cbms[phase][chunk], cpd_size*sizeof(cbm_t));

    free_cbm_hash();
}


/*
// decide whether rule 1 covers rule 2 on a specific field
int rule_pair_cover(uint16_t r1, uint16_t r2, int f)
{
    if (ruleset[r1].field[f].low <= ruleset[r2].field[f].low && 
	    ruleset[r1].field[f].high >= ruleset[r2].field[f].high)
	return 1;
    else
	return 0;
}


// decide whether a rule is redundant in a rule list
int rule_is_redundant(uint16_t r, uint16_t *rules, int nrules, int *rest_fields, range_t covers[][FIELDS])
{
    int		redundant, i, f;
    range_t	*fields = ruleset[r].field;
    pc_rule_t	*p;

    for (i = nrules-1; i >= 0; i--) {
	redundant = 1;
	p = &ruleset[rules[i]];
	for (f = 0; f < FIELDS; f++) {
	    if (rest_fields[f] == 0) 
		continue;

	    if (fields[f].low < covers[i][f].low || fields[f].high > covers[i][f].high)
		return 0;   // no need for more comparisons as no preceding rule can cover it

	    if (fields[f].low < p->field[f].low || fields[f].high > p->field[f].high) {
		redundant = 0;
		break;	    // preceding rule i does not cover rule r, no need to check more fields
	    }
	}
	// redundant keeps 1 only when all fields of rule i have been checked to cover rule r
	// then we can return 1 since a preceding rule i coveres rule r
	if (redundant)
	    return 1;
    }
    return 0;
}


// one more rule is kept in the rule list, and we update the covers array for succeeding rule
// redundancy checking
void update_covers(range_t covers[][FIELDS], int n, pc_rule_t *rule, int *rest_fields)
{
    int	    f;
    
    for (f = 0; f < FIELDS; f++) {
	if (rest_fields[f] == 0)
	    continue;
	covers[n][f].low = MIN(rule->field[f].low, covers[n-1][f].low);
	covers[n][f].high = MAX(rule->field[f].high, covers[n-1][f].high);
    }
}


// compact the intersected rule list by removing redundant rules: a rule is redundant if a preceding
// rule covers it one all rest uncrossproducted fields
int trim_redundant_rules(uint16_t *rules, int nrules, int *rulesum, int *rest_fields)
{
    int		f, i, n, redundant, num_fields = 0;
    range_t	covers[MAXRULES][FIELDS];

    for (f = 0; f < FIELDS; f++) { 
	covers[0][f] = ruleset[rules[0]].field[f];
	num_fields += rest_fields[f];
    }

    if (num_fields == 0) {
	// no rest fields (which means the last phase), simply trim off all rules after the first one
	*rulesum = rules[0];
	return 1;
    }

    n = 1;  // initial number of rules in the (possiblly) trimed rule list
    for (i = 1; i < nrules; i++) {
	if (rule_is_redundant(rules[i], rules, n, rest_fields, covers))
	    continue;	// silently trim the redundant rule off the list

	// move the rule to the correct location if there were redundant preceding rules
	if (n < i)
	    rules[n] = rules[i];

	update_covers(covers, n, &ruleset[rules[i]], rest_fields);
	n++;
    }

    // compute the rulesum for the rule list
    *rulesum = rules[0];
    for (i = 1; i < n; i++)
	*rulesum += rules[i];

    return n;
}


// construct CBM set for current <phase, chunk> by crossproducting two CBM sets from previous phase
void construct_cbm_set(int phase, int chunk, cbm_t *cbms1, int n1, cbm_t *cbms2, int n2)
{
    int		i, j, cbm_id, rulesum, cpd_size = n1 * n2;
    uint16_t	rules[MAXRULES], nrules;

    init_cbm_hash();

    phase_cbms[phase][chunk] = (cbm_t *) malloc(cpd_size*sizeof(cbm_t));
    for (i = 0; i < n1; i++) {
	if ((i & 0xFFF) == 0) // to show the progress for a long crossproducting process
	    fprintf(stderr, "crossprod_2chunk: %6d/%6d\n", i, n1);

	for (j =  0; j < n2; j++) {
	    // 1. generate the intersect of two cbms from two chunks and trim it
	    nrules = cbm_intersect(phase, chunk, &cbms1[i], &cbms2[j], rules, &rulesum);
	    // 2. check whether the intersect cbm exists in crossproducted cbm list so far
	    cbm_id = cbm_lookup(rules, nrules, rulesum, phase_cbms[phase][chunk]);
	    if (cbm_id < 0) // 3. the intersect cbm is new, so add it to the crossproducted cbm list
		cbm_id = new_cbm(phase, chunk, rules, nrules, rulesum);
	    //4. fill the corresponding crossproduct table with the eqid (cmb_id)
	    phase_tables[phase][chunk][i*n2 + j] = cbm_id;
	}
    }
    cpd_size = num_cbms[phase][chunk];
    phase_cbms[phase][chunk] = (cbm_t *) realloc(phase_cbms[phase][chunk], cpd_size*sizeof(cbm_t));

    free_cbm_hash();
}


// there are some CBMs where their rule lists contain redundant rules, by moving these redundant
// rules, some CBMs may become identical and the CBM set can be compacted
void compact_cbm_set(int phase, int chunk, int *rest_fields)
{
    int		i, h, ncbms = 0, cbm_id, *cbm_map;
    cbm_t	*cbm;

    init_cbm_hash();

    cbm_map = (int *) malloc(num_cbms[phase][chunk]*sizeof(int)); 
    for(i = 0; i < num_cbms[phase][chunk]; i++) {
	cbm = &phase_cbms[phase][chunk][i];
	if (cbm->nrules > 1)
	    cbm->nrules= trim_redundant_rules(cbm->rules, cbm->nrules, &(cbm->rulesum), rest_fields);
	cbm_id = cbm_lookup(cbm->rules, cbm->nrules, cbm->rulesum, phase_cbms[phase][chunk]);
	if (cbm_id >= 0) {
	    // this CBM has preceding equivalent CBM, so exclude it from the set
	    cbm_map[cbm->id] = cbm_id;
	    del_cbm(cbm);
	    continue;
	}

	cbm_map[cbm->id] = ncbms;
	if (cbm->id > ncbms) {  
	    // some preceding CBMS removed, need change this one's location
	    cbm->id = ncbms;
	    phase_cbms[phase][chunk][ncbms] = *cbm;
	}
	ncbms++;
	h = cbm->rulesum % HASH_TAB_SIZE;
	add_to_hash(h, cbm);
    }

    num_cbms[phase][chunk] = ncbms;
    phase_cbms[phase][chunk] = (cbm_t *) realloc(phase_cbms[phase][chunk], ncbms*sizeof(cbm_t));

    // refill the phase table with the new CBM ids after compaction
    for (i = 0; i < phase_table_sizes[phase][chunk]; i++) {
	cbm_id = phase_tables[phase][chunk][i];
	phase_tables[phase][chunk][i] = cbm_map[cbm_id];
    }

    free(cbm_map);
    free_cbm_hash();
}
*/



//-------------------------------------------------------------------------------------------------
//
// Section phase-0: functions for phase-0 table generation
//
//-------------------------------------------------------------------------------------------------


// given an end point on a chunk, collect rules covering it
int collect_epoint_rules(int chunk, int point, uint16_t *rules, int *rulesum)
{
    int		f, k, low, high;
    uint16_t	nrules = 0, i;

    f = chunk_to_field[chunk];
    k = shamt[chunk];
    *rulesum = 0;
    for (i = 0; i < numrules; i++) {
	low = ruleset[i].field[f].low >> k & 0xFFFF;
	high = ruleset[i].field[f].high >> k & 0xFFFF;
	if (low <= point && high >= point) {
	    rules[nrules++] = i;
	    *rulesum += i;
	}
    }
    return nrules;
}


// given a pair of neighbor points on a chunk, collect rules falling in their interval
int collect_interval_rules(int chunk, int point1, int point2, uint16_t *rules, int *rulesum)
{
    int		f, k, low, high;
    uint16_t	nrules = 0, i;

    f = chunk_to_field[chunk];
    k = shamt[chunk];
    *rulesum = 0;
    for (i = 0; i < numrules; i++) {
	low = ruleset[i].field[f].low >> k & 0xFFFF;
	high = ruleset[i].field[f].high >> k & 0xFFFF;
	if (low <= point1 && high >= point2) {
	    rules[nrules++] = i;
	    *rulesum += i;
	}
    }
    return nrules;
}


// phase 0: generate CBMs for a chunk in phase 0, and populate the corresponding phase table with
// the corresponding CBM ids
void gen_cbms(int chunk)
{
    uint16_t	rules[MAXRULES], nrules; 
    int		rulesum, point, next_point, cbm_id, i, j, table_size = 65536;


    //phase_table_sizes[0][chunk] = table_size;
    //phase_tables[0][chunk] = (int *) calloc(table_size, sizeof(int));

    init_cbm_hash();

    for (i = 0; i < num_epoints[chunk]; i++) {
	// 1. Collect rules covering an end-point, then create a CBM or match an existing CBM for it
	point = epoints[chunk][i];
	nrules = collect_epoint_rules(chunk, point, rules, &rulesum);
	cbm_id = cbm_lookup(rules, nrules, rulesum, phase_cbms[0][chunk]);
	if (cbm_id < 0)
	    cbm_id = new_cbm(0, chunk, rules, nrules, rulesum);
	//phase_tables[0][chunk][point] = cbm_id;

	// no point interval for the last point, finish the loop
	if (i == num_epoints[chunk] - 1)
	    break;

	next_point = epoints[chunk][i+1];
	// if no interval between [point, next_point], don't do part 2
	if (next_point - point > 1)
	    continue;

	// 2. Collect rules covering interval [point, next_point], 
	// then create a CBM or match an existing CBM for it
	nrules = collect_interval_rules(chunk, point, next_point, rules, &rulesum);
	cbm_id = cbm_lookup(rules, nrules, rulesum, phase_cbms[0][chunk]);
	if (cbm_id < 0)
	    cbm_id = new_cbm(0, chunk, rules, nrules, rulesum);
	/*
	for (j = point+1; j < next_point; j++) {
	    phase_tables[0][chunk][j] = cbm_id;
	}
	*/
    }
    printf("Chunk[%d]: %d CBMs\n", chunk, num_cbms[0][chunk]);

    free_cbm_hash();
}


// phase 0: generate phase tables for phase 0
int gen_p0_tables()
{
    int		chunk;

    for (chunk = 0; chunk < MAXCHUNKS; chunk++) {
	gen_cbms(chunk);
    }
    //dump_intersect_stats();
    bzero(intersect_stats, MAXRULES*2*sizeof(long));
}



//--------------------------------------------------------------------------------------------------
// Section: crossproduct phase functions
//--------------------------------------------------------------------------------------------------


/*
void dump_block(int phase, int block[][BLOCKSIZE], int r, int c)
{
    int	    i, j, f;

    printf("block[%d, %d]:\n", r, c);
    for (i = 0; i < BLOCKSIZE; i++) {
	for (j = 0; j < BLOCKSIZE; j++) {
	    if (phase == 3)
		printf("%3d ", phase_cbms[3][0][block[i][j]].rules[0]);
	    else
		printf("%3d ", block[i][j]);
	}
	printf("\n");
    }
}


// Scan a row in a block to get the prime CBM in this row. Return 1 if success (no more than one
// dirt in this row), otherwise return 0 (2+ dirts)
scan_one_row(int block[][BLOCKSIZE], int row, int col_size, int *primes, int *dirt_cols)
{
    int	    i, j, ids[BLOCKSIZE], id_counts[BLOCKSIZE], num_ids = 0, prime_id, dirt_id;

    for (i = 0; i < col_size; i++) {
	for (j = 0; j < num_ids; j++) {
	    if (block[row][i] == block[row][ids[j]]) {
		id_counts[j]++;
		break;
	    }
	}
	if (j == num_ids) {
	    ids[num_ids] = i;
	    id_counts[num_ids] = 1;
	    num_ids++;
	}
    }

    prime_id = 0;
    for (i = 1; i < num_ids; i++) {
	if (id_counts[i] > id_counts[prime_id])
	    prime_id = i;
    }

    if (num_ids > 2)	// a row-type block only allows one dirt in each row
	return 0;
    if (id_counts[prime_id] < col_size - 1) // a row-type block only allows one dirt in each row
	return 0;

    primes[row] = block[row][ids[prime_id]];
    if (num_ids == 1)
	dirt_cols[row] = 0xFF;	    // 0xFF means no dirt column
    else
	dirt_cols[row] = ids[!prime_id];

    return 1;
}


int row_dirt_encode(int block[][BLOCKSIZE], int row_size, int col_size, 
	int *dirt_locs, dirt_code_t *dirt_code, int *dirts)
{
    int	    i, j, num_dirts = 0;

    num_dirts = 0;
    for (i = 0; i < row_size; i++) {
	if (dirt_locs[i] == 0xFF) {	// no dirt in this row
	    dirt_code[i].id = 0xF;
	    continue;
	}

	for (j = 0; j < num_dirts; j++) {
	    if (block[i][dirt_locs[i]] == dirts[j]) {
		dirt_code[i].loc = dirt_locs[i];
		dirt_code[i].id = j;
		break;
	    }
	}

	if (j == num_dirts) {
	    if (num_dirts == 0xF)   // exceeding 15 dirts, encoding failed and not a row-type block
		return -1;   
	    dirts[num_dirts] = block[i][dirt_locs[i]];
	    dirt_code[i].loc = dirt_locs[i];
	    dirt_code[i].id = num_dirts++;
	}
    }

    return num_dirts;
}


int scan_rows(int block[][BLOCKSIZE], int row_size, int col_size, int *row_primes, 
	dirt_code_t *dirt_code, int *dirts)
{
    int	    i, j, num_dirts, good_row;
    int	    dirt_locs[BLOCKSIZE];

    for (i = 0; i < row_size; i++) {
	good_row = scan_one_row(block, i, col_size, row_primes, dirt_locs);
	if (!good_row)
	    return -1;		// not a row block
    }

    num_dirts = row_dirt_encode(block, row_size, col_size, dirt_locs, dirt_code, dirts);

    return num_dirts;
}


// Scan a column in a block to get the prime CBM in this column. Return 1 if success (no more than one
// dirt in this column), otherwise return 0 (2+ dirts)
scan_one_col(int block[][BLOCKSIZE], int col, int row_size, int *primes, int *dirt_rows)
{
    int	    i, j, ids[BLOCKSIZE], id_counts[BLOCKSIZE], num_ids = 0, prime_id, dirt_id;

    for (i = 0; i < row_size; i++) {
	for (j = 0; j < num_ids; j++) {
	    if (block[i][col] == block[ids[j]][col]) {
		id_counts[j]++;
		break;
	    }
	}
	if (j == num_ids) {
	    ids[num_ids] = i;
	    id_counts[num_ids] = 1;
	    num_ids++;
	}
    }

    prime_id = 0;
    for (i = 1; i < num_ids; i++) {
	if (id_counts[i] > id_counts[prime_id])
	    prime_id = i;
    }

    if (num_ids > 2)	// a col-type block only allows one dirt in each col
	return 0;
    if (id_counts[prime_id] < row_size - 1) // a col-type block only allows one dirt in each col
	return 0;

    primes[col] = block[ids[prime_id]][col];
    if (num_ids == 1)
	dirt_rows[col] = 0xFF;	    // 0xFF means no dirt column
    else
	dirt_rows[col] = ids[!prime_id];

    return 1;
}


int col_dirt_encode(int block[][BLOCKSIZE], int row_size, int col_size, 
	int *dirt_locs, dirt_code_t *dirt_code, int *dirts)
{
    int	    i, j, num_dirts = 0;

    num_dirts = 0;
    for (i = 0; i < col_size; i++) {
	if (dirt_locs[i] == 0xFF) {	// no dirt in this column
	    dirt_code[i].id = 0xF;
	    continue;
	}

	for (j = 0; j < num_dirts; j++) {
	    if (block[i][dirt_locs[i]] == dirts[j]) {
		dirt_code[i].loc = dirt_locs[i];
		dirt_code[i].id = j;
		break;
	    }
	}
	if (j == num_dirts) {
	    if (num_dirts == 0xF)   // exceeding 15 dirts, encoding failed and not a row-type block
		return -1;   
	    dirts[num_dirts] = block[i][dirt_locs[i]];
	    dirt_code[i].loc = dirt_locs[i];
	    dirt_code[i].id = num_dirts++;
	}
    }

    return num_dirts;
}


int scan_cols(int block[][BLOCKSIZE], int row_size, int col_size, int *col_primes, 
	dirt_code_t *dirt_code, int *dirts)
{
    int	    i, j, num_dirts, good_col;
    int	    dirt_locs[BLOCKSIZE];

    for (i = 0; i < col_size; i++) {
	good_col = scan_one_col(block, i, row_size, col_primes, dirt_locs);
	if (!good_col)
	    return -1;		// not a row block
    }

    num_dirts = col_dirt_encode(block, row_size, col_size, dirt_locs, dirt_code, dirts);

    return num_dirts;
}


int new_point_block(int phase, int chunk, int *primes, dirt_code_t *dirt_code, int *dirts, int num_dirts, int pass)
{
    int		    n = point_table_sizes[phase][chunk][pass];
    point_block_t   *table = point_block_tables[phase][chunk][pass];

    if ((n & 0xFF) == 0)
	table = realloc(table, (n + 0x100) * sizeof(point_block_t));

    table[n].prime_cbm = primes[0];
    memcpy(table[n].dirt_code, dirt_code, BLOCKSIZE * sizeof(dirt_code_t));
    table[n].dirts = (int *) malloc(num_dirts * sizeof(int));
    memcpy(table[n].dirts, dirts, num_dirts * sizeof(int));
    table[n].num_dirts = num_dirts;	// can be removed in production system

    point_table_sizes[phase][chunk][pass]++;
    point_block_tables[phase][chunk][pass] = table;
}


int new_row_block(int phase, int chunk, int *primes, dirt_code_t *dirt_code, int *dirts, int num_dirts, int pass)
{
    int		    n = row_table_sizes[phase][chunk][pass];
    array_block_t   *table = row_block_tables[phase][chunk][pass];

    if ((n & 0xFF) == 0)
	table = realloc(table, (n + 0x100) * sizeof(array_block_t));

    memcpy(table[n].prime_cbms, primes, BLOCKSIZE * sizeof(int));
    memcpy(table[n].dirt_code, dirt_code, BLOCKSIZE * sizeof(dirt_code_t));
    table[n].dirts = (int *) malloc(num_dirts * sizeof(int));
    memcpy(table[n].dirts, dirts, num_dirts * sizeof(int));
    table[n].num_dirts = num_dirts;	// can be removed in production system

    row_table_sizes[phase][chunk][pass]++;
    row_block_tables[phase][chunk][pass] = table;
}


int new_col_block(int phase, int chunk, int *primes, dirt_code_t *dirt_code, int *dirts, int num_dirts, int pass)
{
    int		    n = col_table_sizes[phase][chunk][pass];
    array_block_t   *table = col_block_tables[phase][chunk][pass];

    if ((n & 0xFF) == 0)
	table = realloc(table, (n + 0x100) * sizeof(array_block_t));

    memcpy(table[n].prime_cbms, primes, BLOCKSIZE * sizeof(int));
    memcpy(table[n].dirt_code, dirt_code, BLOCKSIZE * sizeof(dirt_code_t));
    table[n].dirts = (int *) malloc(num_dirts * sizeof(int));
    memcpy(table[n].dirts, dirts, num_dirts * sizeof(int));
    table[n].num_dirts = num_dirts;	// can be removed in production system

    col_table_sizes[phase][chunk][pass]++;
    col_block_tables[phase][chunk][pass] = table;
}


int new_matrix_block(int phase, int chunk, int b1, int b2, int block[][BLOCKSIZE], int row_size, int col_size, int pass)
{
    int		    n = matrix_table_sizes[phase][chunk][pass];
    matrix_block_t   *table = matrix_block_tables[phase][chunk][pass];

    if ((n & 0xFF) == 0)
	table = realloc(table, (n + 0x100) * sizeof(matrix_block_t));

    table[n].row_block = b1;
    table[n].col_block = b2;
    table[n].row_size = row_size;
    table[n].col_size = col_size;
    memcpy(table[n].cbms, block, BLOCKSIZE*BLOCKSIZE*sizeof(int));

    matrix_table_sizes[phase][chunk][pass]++;
    matrix_block_tables[phase][chunk][pass] = table;
}


void dump_matrix_block(int phase, int chunk, int block_id, int pass)
{
    int		    i, j;
    matrix_block_t  *block = &matrix_block_tables[phase][chunk][pass][block_id];

    for (i = 0; i < block->row_size; i++) {
	for (j = 0; j < block->col_size; j++) {
	    printf("%4d ", block->cbms[i][j]);
	}
	printf("\n");
    }
}


int new_block(int phase, int chunk, int b1, int b2, int block_type, int block[][BLOCKSIZE], int row_size, int col_size, 
	int *prime_cbms, dirt_code_t *dirt_code, int *dirts, int num_dirts, int pass)
{
    int		    n = block_table_sizes[phase][chunk][pass];
    block_entry_t   *table = block_id_tables[phase][chunk][pass];

    if ((n & 0xFF) == 0)
	table = realloc(table, (n + 0x100) * sizeof(block_entry_t));

    table[n].type = block_type;
    switch (block_type) {
    case POINT_BLOCK:
	table[n].id = point_table_sizes[phase][chunk][pass];
	new_point_block(phase, chunk, prime_cbms, dirt_code, dirts, num_dirts, pass);
	break;
    case ROW_BLOCK:
	table[n].id = row_table_sizes[phase][chunk][pass];
	new_row_block(phase, chunk, prime_cbms, dirt_code, dirts, num_dirts, pass);
	break;
    case COL_BLOCK:
	table[n].id = col_table_sizes[phase][chunk][pass];
	new_col_block(phase, chunk, prime_cbms, dirt_code, dirts, num_dirts, pass);
	break;
    default:	    // MATRIX_BLOCK
	table[n].id = matrix_table_sizes[phase][chunk][pass];
	new_matrix_block(phase, chunk, b1, b2, block, row_size, col_size, pass);
	break;
    }

    block_table_sizes[phase][chunk][pass]++;
    block_id_tables[phase][chunk][pass] = table;
}


int add_block(int phase, int chunk, int b1, int b2, int block[][BLOCKSIZE], int row_size, int col_size, int pass)
{
    int		i, prime_cbms[BLOCKSIZE], dirt_cbms[BLOCKSIZE], num_dirts, block_type = MATRIX_BLOCK;
    dirt_code_t	dirt_code[BLOCKSIZE];

    num_dirts = scan_rows(block, row_size, col_size, prime_cbms, dirt_code, dirt_cbms);
    if (num_dirts >= 0) {   // it's a good row-type block, further decide whether it's a point-type block
	block_type = ROW_BLOCK;
	for (i = 1; i < row_size; i++) {
	    if (prime_cbms[i] != prime_cbms[0])
		break;
	}
	if (i == row_size)  // all rows are the same,so it's a point-type block
	    block_type = POINT_BLOCK;
    } else {	// not a row-type block, decide whether it's a col-type block
	num_dirts = scan_cols(block, row_size, col_size, prime_cbms, dirt_code, dirt_cbms);
	if (num_dirts >= 0)
	    block_type = COL_BLOCK;
    }

    new_block(phase, chunk, b1, b2, block_type, block, row_size, col_size, prime_cbms, 
	    dirt_code, dirt_cbms, num_dirts, pass);
    return block_type;
}


int p3_counts[MAXRULES];

int crossprod_block(int phase, int chunk, int ph1, int ch1, int ph2, int ch2, int b1, int b2)
{
    int		row_start, row_size, col_start, col_size, i, j, rulesum, cbm_id; 
    int		n1 = num_cbms[ph1][ch1], n2 = num_cbms[ph2][ch2];
    uint16_t	rules[MAXRULES], nrules;
    cbm_t	*cbms1, *cbms2;
    int		block[BLOCKSIZE][BLOCKSIZE];

    cbms1 = phase_cbms[ph1][ch1];
    cbms2 = phase_cbms[ph2][ch2];

    row_start = b1 * BLOCKSIZE;
    col_start = b2 * BLOCKSIZE;
    if (n1 - row_start < BLOCKSIZE)
	row_size = n1 - b1*BLOCKSIZE;
    else
	row_size = BLOCKSIZE;
    if (n2 - col_start < BLOCKSIZE)
	col_size = n2 - b2*BLOCKSIZE;
    else
	col_size = BLOCKSIZE;

    //printf("**b%dxb%d**\n", b1, b2);
    for (i = 0; i < row_size; i++) {
	for (j = 0; j < col_size; j++) {
	    nrules = cbm_intersect(phase, chunk, rules, &rulesum, ph1, ch1, row_start+i, ph2, ch2, col_start+j);
	    cbm_id = cbm_lookup(rules, nrules, rulesum, phase_cbms[phase][chunk]);
	    if (cbm_id < 0)
		cbm_id = new_cbm(phase, chunk, rules, nrules, rulesum);

	    block[i][j] = cbm_id;
	    if (phase == 3) {
		p3_counts[phase_cbms[3][0][cbm_id].rules[0]]++;
	    }
	}
    }

    add_block(phase, chunk, b1, b2, block, row_size, col_size, 0);
}


int chunk_table_stats(int phase, int chunk, int pass)
{
    int		i, id, point_dirts = 0, row_dirts = 0, col_dirts = 0; 
    int		prime_size, table_size, dirt_size, total_size;
    int		pblock_size = 8 + BLOCKSIZE;
    int		rblock_size = BLOCKSIZE*4 + 4 + BLOCKSIZE;
    int		cblock_size = rblock_size;
    int		mblock_size = BLOCKSIZE*BLOCKSIZE*4;
    block_entry_t   *table = block_id_tables[phase][chunk][pass];

    for (i = 0; i < block_table_sizes[phase][chunk][pass]; i++) {
	id = table[i].id;
	switch (table[i].type) {
	case POINT_BLOCK:
	    point_dirts += point_block_tables[phase][chunk][pass][id].num_dirts;
	    break;
	case ROW_BLOCK:
	    row_dirts += row_block_tables[phase][chunk][pass][id].num_dirts;
	    break;
	case COL_BLOCK:
	    col_dirts += col_block_tables[phase][chunk][pass][id].num_dirts;
	    break;
	default:
	    break;
	}
    }

    table_size = block_table_sizes[phase][chunk][pass]*sizeof(block_entry_t);
    printf("block_table[%4d]:\t%d bytes\n", block_table_sizes[phase][chunk][pass], table_size);
    total_size = table_size;

    prime_size = point_table_sizes[phase][chunk][pass] * pblock_size;
    dirt_size = point_dirts * sizeof(int);
    table_size = prime_size + dirt_size;
    printf("point_table[%4d]:\t%d bytes (prime: %d, dirts: %d)\n", point_table_sizes[phase][chunk][pass],
	    table_size, prime_size, dirt_size);
    total_size += table_size;

    prime_size = row_table_sizes[phase][chunk][pass] * rblock_size;
    dirt_size = row_dirts * sizeof(int);
    table_size = prime_size + dirt_size;
    printf("row_table[%4d]:\t%d bytes (prime: %d, dirts: %d)\n", row_table_sizes[phase][chunk][pass], 
	    table_size, prime_size, dirt_size);
    total_size += table_size;

    prime_size = col_table_sizes[phase][chunk][pass] * cblock_size;
    dirt_size = col_dirts * sizeof(int);
    table_size = prime_size + dirt_size;
    printf("col_table[%4d]:\t%d bytes (prime: %d, dirts: %d)\n", col_table_sizes[phase][chunk][pass], 
	    table_size, prime_size, dirt_size);
    total_size += table_size;

    table_size = matrix_table_sizes[phase][chunk][pass] * mblock_size;
    printf("matrix_table[%4d]:\t%d bytes\n", matrix_table_sizes[phase][chunk][pass], table_size);
    total_size += table_size;

    printf("Chunk total size:\t%d bytes\n", total_size);

    return total_size;
}


void add_dirt(int ph1, int ch1, int cbm1, int ph2, int ch2, int cbm2)
{
    phase_cbms[ph1][ch1][cbm1].ndirts++;
    phase_cbms[ph2][ch2][cbm2].ndirts++;
}


void scan_block_dirts(matrix_block_t *block, int ph1, int ch1, int ph2, int ch2)
{
    typedef struct {
	int	cbm_id;
	int	count;
    } cbm_count_t;

    int		i, j, k, num_primes = 0, dirt_thresh, cbm1_id, cbm2_id;
    cbm_count_t	primes[BLOCKSIZE*BLOCKSIZE];

    for (i = 0; i < block->row_size; i++) {
	for (j = 0; j < block->col_size; j++) {
	    for (k = 0; k < num_primes; k++) {
		if (block->cbms[i][j] == primes[k].cbm_id) {
		    primes[k].count++;
		    break;
		}
	    }
	    if (k == num_primes) {
		primes[k].cbm_id = block->cbms[i][j];
		primes[k].count = 1;
		num_primes++;
	    }
	}
    }

    dirt_thresh = block->row_size < block->col_size ? block->row_size : block->col_size;
    dirt_thresh >>= 1;

    cbm1_id = block->row_block * BLOCKSIZE;
    for (i = 0; i < block->row_size; i++) {
	cbm2_id = block->col_block * BLOCKSIZE;
	for (j = 0; j < block->col_size; j++) {
	    for (k = 0; k < num_primes; k++) {
		if (block->cbms[i][j] == primes[k].cbm_id) {
		    if (primes[k].count < dirt_thresh)
			add_dirt(ph1, ch1, cbm1_id, ph2, ch2, cbm2_id);
		    break;
		}
	    }
	    cbm2_id++;
	}
	cbm1_id++;
    }

}


static int cbm_dirt_cmp(const void *p, const void *q)
{
    if (((cbm_t *)p)->ndirts > ((cbm_t *)q)->ndirts)
	return 1;
    else if (((cbm_t *)p)->ndirts < ((cbm_t *)q)->ndirts)                                                   
	return -1;                                                     
    else
	return 0;                                                                                   
}


void sort_cbms_by_dirts(int phase, int chunk)
{
    qsort(phase_cbms[phase][chunk], num_cbms[phase][chunk], sizeof(cbm_t), cbm_dirt_cmp);
}


static int cbm_rulesum_cmp(const void *p, const void *q)
{
    if (((cbm_t *)p)->rulesum > ((cbm_t *)q)->rulesum)
	return 1;
    else if (((cbm_t *)p)->rulesum < ((cbm_t *)q)->rulesum)
	return -1;                                                     
    else
	return 0;                                                                                   
}


void sort_cbms_by_rulesum(int phase, int chunk)
{
    qsort(phase_cbms[phase][chunk], num_cbms[phase][chunk], sizeof(cbm_t), cbm_rulesum_cmp);
}


dump_cbm_dirts(int phase, int chunk)
{
    int		i;
    cbm_t	*cbms = phase_cbms[phase][chunk];

    printf("phase_cbm[%d][%d] in #dirts order\n", phase, chunk);
    for (i = 0; i < num_cbms[phase][chunk]; i++) {
	printf("    CBM[%d]: %d\n", cbms[i].id, cbms[i].ndirts);
    }
}


void scan_matrix_blocks(int phase, int chunk, int ph1, int ch1, int ph2, int ch2)
{
    int		    i, n = matrix_table_sizes[phase][chunk][0];
    matrix_block_t  *table = matrix_block_tables[phase][chunk][0];
    

    for (i = 0; i < n; i++) {
	scan_block_dirts(&table[i], ph1, ch1, ph2, ch2);
    }

    //sort_cbms_by_dirts(ph1, ch1);
    dump_cbm_dirts(ph1, ch1);
    //sort_cbms_by_rulesum(ph2, ch2);
    //sort_cbms_by_dirts(ph2, ch2);
    dump_cbm_dirts(ph2, ch2);
}


// shuffle cbms in <ph1, ch1> and <ph2 ,ch2> to make cbms with more dirt contributions clustered
// in the end of each cbm set, s.t. less crossproducted blocks are classified as matrix block
void cbm_shuffle(int phase, int chunk, int ph1, int ch1, int ph2, int ch2)
{
    scan_matrix_blocks(phase, chunk, ph1, ch1, ph2, ch2);
}


int get_point_block_cbm(point_block_t *table, int block_id, int row, int col)
{
    int		    dirt_col, dirt_id, cbm_id;

    dirt_col = table[block_id].dirt_code[row].loc;
    dirt_id = table[block_id].dirt_code[row].id;
    if (dirt_id == 0xF || dirt_col != col) {
	cbm_id = table[block_id].prime_cbm;
    } else {
	cbm_id = table[block_id].dirts[dirt_id];
    }

    return cbm_id;
}


int get_row_block_cbm(array_block_t *table, int block_id, int row, int col)
{
    int		    dirt_col, dirt_id, cbm_id;

    dirt_col = table[block_id].dirt_code[row].loc;
    dirt_id = table[block_id].dirt_code[row].id;
    if (dirt_id == 0xF || dirt_col != col) {
	cbm_id = table[block_id].prime_cbms[row];
    } else {
	cbm_id = table[block_id].dirts[dirt_id];
    }

    return cbm_id;
}


int get_col_block_cbm(array_block_t *table, int block_id, int row, int col)
{
    int		    dirt_row, dirt_id, cbm_id;

    dirt_row = table[block_id].dirt_code[col].loc;
    dirt_id = table[block_id].dirt_code[col].id;
    if (dirt_id == 0xF || dirt_row != row) {
	cbm_id = table[block_id].prime_cbms[col];
    } else {
	cbm_id = table[block_id].dirts[dirt_id];
    }

    return cbm_id;
}


int get_matrix_block_cbm(matrix_block_t *table, int block_id, int row, int col)
{
    return table[block_id].cbms[row][col];
}


int crossprod_block_pass2(int phase, int chunk, int ph1, int ch1, int ph2, int ch2, int b1, int b2)
{
    int		row_start, row_size, col_start, col_size, i, j, rulesum, cbm_id; 
    int		n1 = num_cbms[ph1][ch1], n2 = num_cbms[ph2][ch2];
    uint16_t	rules[MAXRULES], nrules;
    cbm_t	*cbms1, *cbms2;
    int		block[BLOCKSIZE][BLOCKSIZE];
    int		cbm1, cbm2, b1_pass1, b2_pass1, row_pass1, col_pass1, block_id_pass1, block_type, block_type_id;

    cbms1 = phase_cbms[ph1][ch1];
    cbms2 = phase_cbms[ph2][ch2];

    row_start = b1 * BLOCKSIZE;
    col_start = b2 * BLOCKSIZE;
    if (n1 - row_start < BLOCKSIZE)
	row_size = n1 - b1*BLOCKSIZE;
    else
	row_size = BLOCKSIZE;
    if (n2 - col_start < BLOCKSIZE)
	col_size = n2 - b2*BLOCKSIZE;
    else
	col_size = BLOCKSIZE;

    //printf("**b%dxb%d**\n", b1, b2);
    for (i = 0; i < row_size; i++) {
	cbm1 = cbms1[row_start + i].id;
	b1_pass1 = cbm1 / BLOCKSIZE;
	row_pass1 = cbm1 % BLOCKSIZE;
	for (j = 0; j < col_size; j++) {
	    cbm2 = cbms2[col_start + j].id;
	    b2_pass1 = cbm2 / BLOCKSIZE;
	    col_pass1 = cbm2 % BLOCKSIZE;
	    block_id_pass1 = b1_pass1 * b2_pass1;
	    block_type = block_id_tables[phase][chunk][0][block_id_pass1].type;
	    block_type_id = block_id_tables[phase][chunk][0][block_id_pass1].id;

	    switch (block_type) {
	    case POINT_BLOCK:
		cbm_id = get_point_block_cbm(point_block_tables[phase][chunk][0], block_type_id, row_pass1, col_pass1);
		break;
	    case ROW_BLOCK:
		cbm_id = get_row_block_cbm(row_block_tables[phase][chunk][0], block_type_id, row_pass1, col_pass1);
		break;
	    case COL_BLOCK:
		cbm_id = get_col_block_cbm(col_block_tables[phase][chunk][0], block_type_id, row_pass1, col_pass1);
		break;
	    default:
		cbm_id = get_matrix_block_cbm(matrix_block_tables[phase][chunk][0], block_type_id, row_pass1, col_pass1);
		break;
	    }

	    block[i][j] = cbm_id;
	}
    }

    add_block(phase, chunk, b1, b2, block, row_size, col_size, 1);
}


int crossprod_chunks(int phase, int chunk)
{
    int	    ph1, ph2, ch1, ch2, n1, n2, nb1, nb2, i, j, chunk_size;

    init_cbm_hash();

    ph1 = ph2 = phase - 1;

    switch (phase) {
    case 1:
	if (chunk == 0) {
	    ch1 = 1; ch2 = 0;
	} else if (chunk == 1) {
	    ch1 = 3; ch2 = 2;
	} else {
	    ch1 = 6; ch2 = 5;
	}
	break;
    case 2:
	if (chunk == 0) {
	    ch1 = 0; ch2 = 1;
	} else {
	    // ALERT: PROTO (chunk[4] in phase 0) x (DP x SP) (chunk[1] in phase 1)
	    ph2 = 0;
	    ch2 = 4; ch1 = 2;
	}
	break;
    default:	    // phase 3 => the final phase
	ch1 = 0; ch2 = 1;
	break;
    }

    n1 = num_cbms[ph1][ch1];
    n2 = num_cbms[ph2][ch2];
    nb1 = n1 / BLOCKSIZE;
    if (n1 % BLOCKSIZE != 0) nb1++;
    nb2 = n2 / BLOCKSIZE;
    if (n2 % BLOCKSIZE != 0) nb2++;

    for (i = 0; i < nb1; i++) {
	for (j = 0; j < nb2; j++)
	    crossprod_block(phase, chunk, ph1, ch1, ph2, ch2, i, j);
    }

    printf("*** pass 1 ***\n");
    printf("Chunk[%d]: %d CBMs\n", chunk, num_cbms[phase][chunk]);
    chunk_size = chunk_table_stats(phase, chunk, 0);


    free_cbm_hash();

    return chunk_size;
}


// do phase 1 crossproducting for three pairs of chunks in phase 0,
// Alert 1: the protocol chunk is left for crossproducting in next phase
// Alert 2: be careful of the order of crosspoducting for each pair of chunks (as commented in below code)
int p1_crossprod()
{
    int	    phase_size;

    // SIP[31:16] x SIP[15:0]
    phase_size = crossprod_chunks(1, 0);

    // DIP[31:16] x DIP[15:0]
    phase_size += crossprod_chunks(1, 1);

    // DP x SP
    phase_size += crossprod_chunks(1, 2);

    bzero(intersect_stats, MAXRULES*2*sizeof(long));

    printf("Phase total size:\t%d bytes\n", phase_size);
    return phase_size;
}


// do phase 2 crossproducting for two pairs of chunks,
// Alert: three chunks (SIP, DIP, Ports) are from phase 1, and one chunk (protocol field) from phase 0.
// Alert: pay attention of their orders in crossproducting
int p2_crossprod()
{
    int	    phase_size;

    // SIP x DIP
    phase_size = crossprod_chunks(2, 0);

    // PROTO x (DP x SP)
    phase_size += crossprod_chunks(2, 1);

    bzero(intersect_stats, MAXRULES*2*sizeof(long));

    printf("Phase total size:\t%d bytes\n", phase_size);
    return phase_size;
}


void p3_stats()
{
    int	    i;

    qsort(p3_counts, numrules, sizeof(int), point_cmp);
    for (i = 0; i < numrules; i++) {
	printf("rule[%d]: %d\n", i, p3_counts[i]);
    }

}
*/


/*
int cheat_sort_p3()
{
    int		i;

    for (i = 0; i < num_cbms[2][1]; i++)
	phase_cbms[2][1][i].ndirts = 32;

    phase_cbms[2][1][3].ndirts = 1;
    phase_cbms[2][1][9].ndirts = 2;
    phase_cbms[2][1][23].ndirts = 3;
    phase_cbms[2][1][25].ndirts = 4;
    phase_cbms[2][1][27].ndirts = 5;
    phase_cbms[2][1][37].ndirts = 6;
    phase_cbms[2][1][42].ndirts = 7;
    phase_cbms[2][1][44].ndirts = 8;
    phase_cbms[2][1][47].ndirts = 9;
    phase_cbms[2][1][49].ndirts = 10;
    phase_cbms[2][1][53].ndirts = 11;
    phase_cbms[2][1][55].ndirts = 12;
    phase_cbms[2][1][35].ndirts = 13;
    phase_cbms[2][1][41].ndirts = 14;
    phase_cbms[2][1][33].ndirts = 15;
    phase_cbms[2][1][7].ndirts = 16;

    sort_cbms_by_dirts(2, 1);

}


int p3_crossprod()
{
    int	    phase_size;

cheat_sort_p3();

    phase_size = crossprod_chunks(3, 0);

    p3_stats();
    printf("Phase total size:\t%d bytes\n", phase_size);
    return phase_size;
}
*/


static int cbm_run_cmp(const void *p, const void *q)
{
    if (((cbm_t *)p)->run > ((cbm_t *)q)->run)
	return 1;
    else if (((cbm_t *)p)->run < ((cbm_t *)q)->run)                                                   
	return -1;                                                     
    else
	return 0;                                                                                   
}


void sort_cbms_by_run(int phase, int chunk)
{
    qsort(phase_cbms[phase][chunk], num_cbms[phase][chunk], sizeof(cbm_t), cbm_run_cmp);
}


void dump_block(int phase, int block[][BLOCKSIZE], int r, int c)
{
    int	    i, j, f;

    printf("block[%d, %d]:\n", r, c);
    for (i = 0; i < BLOCKSIZE; i++) {
	for (j = 0; j < BLOCKSIZE; j++) {
	    if (phase == 3)
		printf("%3d ", phase_cbms[3][0][block[i][j]].rules[0]);
	    else
		printf("%3d ", block[i][j]);
	}
	printf("\n");
    }
}


// Scan a row in a block to get the prime CBM in this row. Return 1 if success (no more than one
// dirt in this row), otherwise return 0 (2+ dirts)
scan_one_row(int block[][BLOCKSIZE], int row, int col_size, int *primes, int *dirt_cols)
{
    int	    i, j, ids[BLOCKSIZE], id_counts[BLOCKSIZE], num_ids = 0, prime_id, dirt_id;

    for (i = 0; i < col_size; i++) {
	for (j = 0; j < num_ids; j++) {
	    if (block[row][i] == block[row][ids[j]]) {
		id_counts[j]++;
		break;
	    }
	}
	if (j == num_ids) {
	    ids[num_ids] = i;
	    id_counts[num_ids] = 1;
	    num_ids++;
	}
    }

    prime_id = 0;
    for (i = 1; i < num_ids; i++) {
	if (id_counts[i] > id_counts[prime_id])
	    prime_id = i;
    }

    if (num_ids > 2)	// a row-type block only allows one dirt in each row
	return 0;
    if (id_counts[prime_id] < col_size - 1) // a row-type block only allows one dirt in each row
	return 0;

    primes[row] = block[row][ids[prime_id]];
    if (num_ids == 1)
	dirt_cols[row] = 0xFF;	    // 0xFF means no dirt column
    else
	dirt_cols[row] = ids[!prime_id];

    return 1;
}


int row_dirt_encode(int block[][BLOCKSIZE], int row_size, int col_size, 
	int *dirt_locs, dirt_code_t *dirt_code, int *dirts)
{
    int	    i, j, num_dirts = 0;

    num_dirts = 0;
    for (i = 0; i < row_size; i++) {
	if (dirt_locs[i] == 0xFF) {	// no dirt in this row
	    dirt_code[i].id = 0xF;
	    continue;
	}

	for (j = 0; j < num_dirts; j++) {
	    if (block[i][dirt_locs[i]] == dirts[j]) {
		dirt_code[i].loc = dirt_locs[i];
		dirt_code[i].id = j;
		break;
	    }
	}

	if (j == num_dirts) {
	    if (num_dirts == 0xF)   // exceeding 15 dirts, encoding failed and not a row-type block
		return -1;   
	    dirts[num_dirts] = block[i][dirt_locs[i]];
	    dirt_code[i].loc = dirt_locs[i];
	    dirt_code[i].id = num_dirts++;
	}
    }

    return num_dirts;
}


int scan_rows(int block[][BLOCKSIZE], int row_size, int col_size, int *row_primes, 
	dirt_code_t *dirt_code, int *dirts)
{
    int	    i, j, num_dirts, good_row;
    int	    dirt_locs[BLOCKSIZE];

    for (i = 0; i < row_size; i++) {
	good_row = scan_one_row(block, i, col_size, row_primes, dirt_locs);
	if (!good_row)
	    return -1;		// not a row block
    }

    num_dirts = row_dirt_encode(block, row_size, col_size, dirt_locs, dirt_code, dirts);

    return num_dirts;
}


// Scan a column in a block to get the prime CBM in this column. Return 1 if success (no more than one
// dirt in this column), otherwise return 0 (2+ dirts)
scan_one_col(int block[][BLOCKSIZE], int col, int row_size, int *primes, int *dirt_rows)
{
    int	    i, j, ids[BLOCKSIZE], id_counts[BLOCKSIZE], num_ids = 0, prime_id, dirt_id;

    for (i = 0; i < row_size; i++) {
	for (j = 0; j < num_ids; j++) {
	    if (block[i][col] == block[ids[j]][col]) {
		id_counts[j]++;
		break;
	    }
	}
	if (j == num_ids) {
	    ids[num_ids] = i;
	    id_counts[num_ids] = 1;
	    num_ids++;
	}
    }

    prime_id = 0;
    for (i = 1; i < num_ids; i++) {
	if (id_counts[i] > id_counts[prime_id])
	    prime_id = i;
    }

    if (num_ids > 2)	// a col-type block only allows one dirt in each col
	return 0;
    if (id_counts[prime_id] < row_size - 1) // a col-type block only allows one dirt in each col
	return 0;

    primes[col] = block[ids[prime_id]][col];
    if (num_ids == 1)
	dirt_rows[col] = 0xFF;	    // 0xFF means no dirt column
    else
	dirt_rows[col] = ids[!prime_id];

    return 1;
}


int col_dirt_encode(int block[][BLOCKSIZE], int row_size, int col_size, 
	int *dirt_locs, dirt_code_t *dirt_code, int *dirts)
{
    int	    i, j, num_dirts = 0;

    num_dirts = 0;
    for (i = 0; i < col_size; i++) {
	if (dirt_locs[i] == 0xFF) {	// no dirt in this column
	    dirt_code[i].id = 0xF;
	    continue;
	}

	for (j = 0; j < num_dirts; j++) {
	    if (block[i][dirt_locs[i]] == dirts[j]) {
		dirt_code[i].loc = dirt_locs[i];
		dirt_code[i].id = j;
		break;
	    }
	}
	if (j == num_dirts) {
	    if (num_dirts == 0xF)   // exceeding 15 dirts, encoding failed and not a row-type block
		return -1;   
	    dirts[num_dirts] = block[i][dirt_locs[i]];
	    dirt_code[i].loc = dirt_locs[i];
	    dirt_code[i].id = num_dirts++;
	}
    }

    return num_dirts;
}


int scan_cols(int block[][BLOCKSIZE], int row_size, int col_size, int *col_primes, 
	dirt_code_t *dirt_code, int *dirts)
{
    int	    i, j, num_dirts, good_col;
    int	    dirt_locs[BLOCKSIZE];

    for (i = 0; i < col_size; i++) {
	good_col = scan_one_col(block, i, row_size, col_primes, dirt_locs);
	if (!good_col)
	    return -1;		// not a row block
    }

    num_dirts = col_dirt_encode(block, row_size, col_size, dirt_locs, dirt_code, dirts);

    return num_dirts;
}


int new_point_block(int phase, int chunk, int *primes, dirt_code_t *dirt_code, int *dirts, int num_dirts)
{
    int		    n = point_table_sizes[phase][chunk];
    point_block_t   *table = point_block_tables[phase][chunk];

    if ((n & 0xFF) == 0)
	table = realloc(table, (n + 0x100) * sizeof(point_block_t));

    table[n].prime_cbm = primes[0];
    memcpy(table[n].dirt_code, dirt_code, BLOCKSIZE * sizeof(dirt_code_t));
    table[n].dirts = (int *) malloc(num_dirts * sizeof(int));
    memcpy(table[n].dirts, dirts, num_dirts * sizeof(int));
    table[n].num_dirts = num_dirts;	// can be removed in production system

    point_table_sizes[phase][chunk]++;
    point_block_tables[phase][chunk] = table;
}


int new_row_block(int phase, int chunk, int *primes, dirt_code_t *dirt_code, int *dirts, int num_dirts)
{
    int		    n = row_table_sizes[phase][chunk];
    array_block_t   *table = row_block_tables[phase][chunk];

    if ((n & 0xFF) == 0)
	table = realloc(table, (n + 0x100) * sizeof(array_block_t));

    memcpy(table[n].prime_cbms, primes, BLOCKSIZE * sizeof(int));
    memcpy(table[n].dirt_code, dirt_code, BLOCKSIZE * sizeof(dirt_code_t));
    table[n].dirts = (int *) malloc(num_dirts * sizeof(int));
    memcpy(table[n].dirts, dirts, num_dirts * sizeof(int));
    table[n].num_dirts = num_dirts;	// can be removed in production system

    row_table_sizes[phase][chunk]++;
    row_block_tables[phase][chunk] = table;
}


int new_col_block(int phase, int chunk, int *primes, dirt_code_t *dirt_code, int *dirts, int num_dirts)
{
    int		    n = col_table_sizes[phase][chunk];
    array_block_t   *table = col_block_tables[phase][chunk];

    if ((n & 0xFF) == 0)
	table = realloc(table, (n + 0x100) * sizeof(array_block_t));

    memcpy(table[n].prime_cbms, primes, BLOCKSIZE * sizeof(int));
    memcpy(table[n].dirt_code, dirt_code, BLOCKSIZE * sizeof(dirt_code_t));
    table[n].dirts = (int *) malloc(num_dirts * sizeof(int));
    memcpy(table[n].dirts, dirts, num_dirts * sizeof(int));
    table[n].num_dirts = num_dirts;	// can be removed in production system

    col_table_sizes[phase][chunk]++;
    col_block_tables[phase][chunk] = table;
}


int new_matrix_block(int phase, int chunk, int b1, int b2, int block[][BLOCKSIZE], int row_size, int col_size)
{
    int		    n = matrix_table_sizes[phase][chunk];
    matrix_block_t   *table = matrix_block_tables[phase][chunk];

    if ((n & 0xFF) == 0)
	table = realloc(table, (n + 0x100) * sizeof(matrix_block_t));

    table[n].row_block = b1;
    table[n].col_block = b2;
    table[n].row_size = row_size;
    table[n].col_size = col_size;
    memcpy(table[n].cbms, block, BLOCKSIZE*BLOCKSIZE*sizeof(int));

    matrix_table_sizes[phase][chunk]++;
    matrix_block_tables[phase][chunk] = table;
    
printf("block[%d] = (%d x %d)\n", n, b1, b2);
}


void dump_matrix_block(int phase, int chunk, int block_id)
{
    int		    i, j;
    matrix_block_t  *block = &matrix_block_tables[phase][chunk][block_id];

    for (i = 0; i < block->row_size; i++) {
	for (j = 0; j < block->col_size; j++) {
	    printf("%4d ", block->cbms[i][j]);
	}
	printf("\n");
    }
}


int new_block(int phase, int chunk, int b1, int b2, int block_type, int block[][BLOCKSIZE], int row_size, 
	int col_size, int *prime_cbms, dirt_code_t *dirt_code, int *dirts, int num_dirts)
{
    int		    n = block_table_sizes[phase][chunk];
    block_entry_t   *table = block_id_tables[phase][chunk];

    if ((n & 0xFF) == 0)
	table = realloc(table, (n + 0x100) * sizeof(block_entry_t));

    table[n].type = block_type;
    switch (block_type) {
    case POINT_BLOCK:
	table[n].id = point_table_sizes[phase][chunk];
	new_point_block(phase, chunk, prime_cbms, dirt_code, dirts, num_dirts);
	break;
    case ROW_BLOCK:
	table[n].id = row_table_sizes[phase][chunk];
	new_row_block(phase, chunk, prime_cbms, dirt_code, dirts, num_dirts);
	break;
    case COL_BLOCK:
	table[n].id = col_table_sizes[phase][chunk];
	new_col_block(phase, chunk, prime_cbms, dirt_code, dirts, num_dirts);
	break;
    default:	    // MATRIX_BLOCK
	table[n].id = matrix_table_sizes[phase][chunk];
	new_matrix_block(phase, chunk, b1, b2, block, row_size, col_size);
	break;
    }

    block_table_sizes[phase][chunk]++;
    block_id_tables[phase][chunk] = table;
}


int add_block(int phase, int chunk, int b1, int b2, int block[][BLOCKSIZE], int row_size, int col_size)
{
    int		i, prime_cbms[BLOCKSIZE], dirt_cbms[BLOCKSIZE], num_dirts, block_type = MATRIX_BLOCK;
    dirt_code_t	dirt_code[BLOCKSIZE];

    num_dirts = scan_rows(block, row_size, col_size, prime_cbms, dirt_code, dirt_cbms);
    if (num_dirts >= 0) {   // it's a good row-type block, further decide whether it's a point-type block
	block_type = ROW_BLOCK;
	for (i = 1; i < row_size; i++) {
	    if (prime_cbms[i] != prime_cbms[0])
		break;
	}
	if (i == row_size)  // all rows are the same,so it's a point-type block
	    block_type = POINT_BLOCK;
    } else {	// not a row-type block, decide whether it's a col-type block
	num_dirts = scan_cols(block, row_size, col_size, prime_cbms, dirt_code, dirt_cbms);
	if (num_dirts >= 0)
	    block_type = COL_BLOCK;
    }

    new_block(phase, chunk, b1, b2, block_type, block, row_size, col_size, prime_cbms, 
	    dirt_code, dirt_cbms, num_dirts);
    return block_type;
}


int construct_block(int phase, int chunk, int ph1, int ch1, int ph2, int ch2, int b1, int b2)
{
    int		row_start, row_size, col_start, col_size, i, j, rulesum, cbm_id; 
    int		n1 = num_cbms[ph1][ch1], n2 = num_cbms[ph2][ch2];
    uint16_t	rules[MAXRULES], nrules;
    cbm_t	*cbms1, *cbms2;
    int		block[BLOCKSIZE][BLOCKSIZE];
    int		cbm1_id, cbm2_id, base, block_type, block_type_id;

    cbms1 = phase_cbms[ph1][ch1];
    cbms2 = phase_cbms[ph2][ch2];

    row_start = b1 * BLOCKSIZE;
    if (n1 - row_start < BLOCKSIZE)
	row_size = n1 - b1*BLOCKSIZE;
    else
	row_size = BLOCKSIZE;

    col_start = b2 * BLOCKSIZE;
    if (n2 - col_start < BLOCKSIZE)
	col_size = n2 - b2*BLOCKSIZE;
    else
	col_size = BLOCKSIZE;

    //printf("**b%dxb%d**\n", b1, b2);
    for (i = 0; i < row_size; i++) {
	cbm1_id = cbms1[row_start + i].id;
	base = cbm1_id * n2;
	for (j = 0; j < col_size; j++) {
	    cbm2_id = cbms2[col_start + j].id;
	    cbm_id = phase_tables[phase][chunk][base + cbm2_id];
	    block[i][j] = cbm_id;
	}
    }

    add_block(phase, chunk, b1, b2, block, row_size, col_size);
}


int chunk_table_stats(int phase, int chunk)
{
    int		i, id, point_dirts = 0, row_dirts = 0, col_dirts = 0; 
    int		prime_size, table_size, dirt_size, total_size;
    int		pblock_size = 8 + BLOCKSIZE;
    int		rblock_size = BLOCKSIZE*4 + 4 + BLOCKSIZE;
    int		cblock_size = rblock_size;
    int		mblock_size = BLOCKSIZE*BLOCKSIZE*4;
    block_entry_t   *table = block_id_tables[phase][chunk];

    for (i = 0; i < block_table_sizes[phase][chunk]; i++) {
	id = table[i].id;
	switch (table[i].type) {
	case POINT_BLOCK:
	    point_dirts += point_block_tables[phase][chunk][id].num_dirts;
	    break;
	case ROW_BLOCK:
	    row_dirts += row_block_tables[phase][chunk][id].num_dirts;
	    break;
	case COL_BLOCK:
	    col_dirts += col_block_tables[phase][chunk][id].num_dirts;
	    break;
	default:
	    break;
	}
    }

    table_size = block_table_sizes[phase][chunk] * sizeof(block_entry_t);
    printf("block_table[%4d]:\t%d bytes\n", block_table_sizes[phase][chunk], table_size);
    total_size = table_size;

    prime_size = point_table_sizes[phase][chunk] * pblock_size;
    dirt_size = point_dirts * sizeof(int);
    table_size = prime_size + dirt_size;
    printf("point_table[%4d]:\t%d bytes (prime: %d, dirts: %d)\n", point_table_sizes[phase][chunk],
	    table_size, prime_size, dirt_size);
    total_size += table_size;

    prime_size = row_table_sizes[phase][chunk] * rblock_size;
    dirt_size = row_dirts * sizeof(int);
    table_size = prime_size + dirt_size;
    printf("row_table[%4d]:\t%d bytes (prime: %d, dirts: %d)\n", row_table_sizes[phase][chunk], 
	    table_size, prime_size, dirt_size);
    total_size += table_size;

    prime_size = col_table_sizes[phase][chunk] * cblock_size;
    dirt_size = col_dirts * sizeof(int);
    table_size = prime_size + dirt_size;
    printf("col_table[%4d]:\t%d bytes (prime: %d, dirts: %d)\n", col_table_sizes[phase][chunk], 
	    table_size, prime_size, dirt_size);
    total_size += table_size;

    table_size = matrix_table_sizes[phase][chunk] * mblock_size;
    printf("matrix_table[%4d]:\t%d bytes\n", matrix_table_sizes[phase][chunk], table_size);
    total_size += table_size;

    printf("Chunk total size:\t%d bytes\n", total_size);

    return total_size;
}


int construct_block_tables(int phase, int chunk)
{
    int	    ph1, ph2, ch1, ch2, n1, n2, nb1, nb2, i, j, chunk_size;

    init_cbm_hash();

    ph1 = ph2 = phase - 1;

    switch (phase) {
    case 1:
	if (chunk == 0) {
	    ch1 = 1; ch2 = 0;
	} else if (chunk == 1) {
	    ch1 = 3; ch2 = 2;
	} else {
	    ch1 = 6; ch2 = 5;
	}
	break;
    case 2:
	if (chunk == 0) {
	    ch1 = 0; ch2 = 1;
	} else {
	    // ALERT: PROTO (chunk[4] in phase 0) x (DP x SP) (chunk[1] in phase 1)
	    ph2 = 0;
	    ch2 = 4; ch1 = 2;
	}
	break;
    default:	    // phase 3 => the final phase
	ch1 = 0; ch2 = 1;
	break;
    }

    n1 = num_cbms[ph1][ch1];
    n2 = num_cbms[ph2][ch2];
    nb1 = n1 / BLOCKSIZE;
    if (n1 % BLOCKSIZE != 0) nb1++;
    nb2 = n2 / BLOCKSIZE;
    if (n2 % BLOCKSIZE != 0) nb2++;

    for (i = 0; i < nb1; i++) {
	for (j = 0; j < nb2; j++)
	    construct_block(phase, chunk, ph1, ch1, ph2, ch2, i, j);
    }

    chunk_size = chunk_table_stats(phase, chunk);

    free_cbm_hash();

    return chunk_size;
}


// do phase 1 crossproducting for three pairs of chunks in phase 0,
// Alert 1: the protocol chunk is left for crossproducting in next phase
// Alert 2: be careful of the order of crosspoducting for each pair of chunks (as commented in below code)
int p1_crossprod()
{
    int	    table_size, n1, n2;
    cbm_t   *cbms1, *cbms2;
    int	    rest_fields[FIELDS] = {1, 1, 1, 1, 1};

    // SIP[31:16] x SIP[15:0]
    n1 = num_cbms[0][1];
    n2 = num_cbms[0][0];
    table_size = n1 * n2;
    cbms1 = phase_cbms[0][1];
    cbms2 = phase_cbms[0][0];
    phase_table_sizes[1][0] = table_size;
    phase_tables[1][0] = (int *) malloc(table_size*sizeof(int));
    crossprod_2chunk(1, 0, cbms1, n1, cbms2, n2);
    printf("chunk[%d]: %d CBMs in Table[%d]\n", 0, num_cbms[1][0], table_size);

    // DIP[31:16] x DIP[15:0]
    n1 = num_cbms[0][3];
    n2 = num_cbms[0][2];
    table_size = n1 * n2;
    cbms1 = phase_cbms[0][3];
    cbms2 = phase_cbms[0][2];
    phase_table_sizes[1][1] = table_size;
    phase_tables[1][1] = (int *) malloc(table_size*sizeof(int));
    crossprod_2chunk(1, 1, cbms1, n1, cbms2, n2);
    printf("Chunk[%d]: %d CBMs in Table[%d]\n", 1, num_cbms[1][1], table_size);

    // DP x SP
    n1 = num_cbms[0][6];
    n2 = num_cbms[0][5];
    table_size = n1 * n2;
    cbms1 = phase_cbms[0][6];
    cbms2 = phase_cbms[0][5];
    phase_table_sizes[1][2] = table_size;
    phase_tables[1][2] = (int *) malloc(table_size*sizeof(int));
    crossprod_2chunk(1, 2, cbms1, n1, cbms2, n2);
    printf("Chunk[%d]: %d CBMs in Table[%d]\n", 2,num_cbms[1][2], table_size);

    //dump_intersect_stats();
    bzero(intersect_stats, MAXRULES*2*sizeof(long));
}


// do phase 2 crossproducting for two pairs of chunks,
// Alert: three chunks (SIP, DIP, Ports) are from phase 1, and one chunk (protocol field) from phase 0.
// Alert: pay attention of their orders in crossproducting
int p2_crossprod()
{
    int	    table_size, n1, n2;
    cbm_t   *cbms1, *cbms2;
    int	    rest_fields[FIELDS] = {0, 0, 1, 1, 1};

    // SIP x DIP
    n1 = num_cbms[1][0];
    n2 = num_cbms[1][1];
    table_size = n1 * n2;
    cbms1 = phase_cbms[1][0];
    cbms2 = phase_cbms[1][1];
    phase_table_sizes[2][0] = table_size;
    phase_tables[2][0] = (int *) malloc(table_size*sizeof(int));
    crossprod_2chunk(2, 0, cbms1, n1, cbms2, n2);
    printf("Chunk[%d]: %d CBMs in Table[%d]\n", 0, num_cbms[2][0], table_size);

    // PROTO x (DP x SP)
    rest_fields[0] = rest_fields[1] = 1;
    rest_fields[2] = rest_fields[3] = rest_fields[4] = 0;
    n1 = num_cbms[0][4];
    n2 = num_cbms[1][2];
    table_size = n1 * n2;
    cbms1 = phase_cbms[0][4];	// Alert: unlike the other 3 chunks, this chunk is an orphant from phase 0
    cbms2 = phase_cbms[1][2];
    phase_table_sizes[2][1] = table_size;
    phase_tables[2][1] = (int *) malloc(table_size*sizeof(int));
    crossprod_2chunk(2, 1, cbms1, n1, cbms2, n2);
    printf("Chunk[%d]: %d CBMs in Table[%d]\n", 0, num_cbms[2][1], table_size);

    //dump_intersect_stats();
    bzero(intersect_stats, MAXRULES*2*sizeof(long));
}


void dump_cbm_runs(int phase, int chunk)
{
    int	    i;

    printf("CBM[%d][%d] runs: \n", phase, chunk);
    for (i = 0; i < num_cbms[phase][chunk]; i++) {
	printf("cbm[%d]: %d runs\n", i, phase_cbms[phase][chunk][i].run);
    }
}


void dump_table_column(int phase, int chunk, int n1, int n2, int col)
{
    int		i, n = n1 * n2;

    printf("Col Table[][%d]: \n", col);
    for (i = col; i < n; i += n2)
	printf("%7d: %6d\n", i/n2, phase_tables[phase][chunk][i]);
	//printf("cbm[%d][%d]: \t%d\n", i, col, phase_tables[phase][chunk][i]);
}


// do crossproducting for two pairs of chunks for the last phase
int p3_crossprod()
{
    int	    table_size, n1, n2, i;
    cbm_t   *cbms1, *cbms2;
    int	    rest_fields[FIELDS] = {0, 0, 0, 0, 0};

    // (SIP x DIP) x (PROTO x (DP x SP))
    n1 = num_cbms[2][0];
    n2 = num_cbms[2][1];
    table_size = n1 * n2;
    cbms1 = phase_cbms[2][0];
    cbms2 = phase_cbms[2][1];
    phase_table_sizes[3][0] = table_size;
    phase_tables[3][0] = (int *) malloc(table_size*sizeof(int));
    crossprod_2chunk(3, 0, cbms1, n1, cbms2, n2);
    printf("Chunk[%d]: %d CBMs in Table[%d]\n", 0, num_cbms[3][0], table_size);

    /*
    for (i = 0; i < num_cbms[2][0]; i++)
	phase_cbms[2][0][i].run >>= 2;
    for (i = 0; i < num_cbms[2][1]; i++)
	phase_cbms[2][1][i].run >>= 8;
    */

    dump_table_column(3, 0, n1, n2, 0);
    dump_table_column(3, 0, n1, n2, 1);
    dump_cbm_runs(2, 0);
    dump_cbm_runs(2, 1);

    sort_cbms_by_run(2, 0);
    sort_cbms_by_run(2, 1);
printf("After sorting...\n");
    dump_cbm_runs(2, 0);
    dump_cbm_runs(2, 1);

    construct_block_tables(3, 0);

    matrix_block_t  *table = matrix_block_tables[3][0];
    for (i = 0; i < matrix_table_sizes[3][0]; i++) {
	printf("matrix[%d]\n", i);
	dump_matrix_block(3, 0, i);
    }

    //dump_intersect_stats();
}


// statistics on the sizes of CBM sets and phase tables
/*
int do_rfc_stats()
{
    int	    i, phase_total[4] = {0, 0, 0, 0}, total = 0;

    printf("\nPhase 0:\n");
    printf("====================\n");
    for (i = 0; i < 7; i++) {
	printf("#cbm/#phase-table %d: %d/%d\n", i, num_cbms[0][i], 65536);
	phase_total[0] += 65536;
    }
    printf("Total phase-table size: %d\n", phase_total[0]);

    printf("\nPhase 1:\n");
    printf("====================\n");
    for (i = 0; i < 3; i++) {
	printf("#cbm/#phase-table %d: %d/%d\n", i, num_cbms[1][i], phase_table_sizes[1][i]);
	phase_total[1] += phase_table_sizes[1][i];
    }
    printf("Total phase-table size: %d\n", phase_total[1]);
    printf("\nPhase 2:\n");
    printf("====================\n");
    for (i = 0; i < 2; i++) {
	printf("#cbm/#phase-table %d: %d/%d\n", i, num_cbms[2][i], phase_table_sizes[2][i]);
	phase_total[2] += phase_table_sizes[2][i];
    }
    printf("Total phase-table size: %d\n", phase_total[2]);

    printf("\nPhase 3:\n");
    printf("====================\n");
    printf("#cbm/#phase-table %d: %d/%d\n", i, num_cbms[3][0], phase_table_sizes[3][0]);
    phase_total[3] = phase_table_sizes[3][0];

    for (i = 0; i < 4; i++)
	total += phase_total[i];
    printf("\nTotal table size: %d\n", total);
}
*/


// constructing the RFC tables with a 3-phase process
void construct_rfc()
{
    int	    total_size;
    clock_t t;

    gen_endpoints();
    dump_endpoints();

    t = clock();
    gen_p0_tables();
    total_size = 65536 * 7 * sizeof(int);
    printf("***Phase 0 spent %lds\n\n", (clock()-t)/1000000);

    t = clock();
    total_size += p1_crossprod();
    printf("***Phase 1 spent %lds\n\n", (clock()-t)/1000000);

    t = clock();
    total_size += p2_crossprod();
    printf("***Phase 2 spent %lds\n\n", (clock()-t)/1000000);

    t = clock();
    total_size += p3_crossprod();
    printf("***Phase 3 spent %lds\n\n", (clock()-t)/1000000);

    /*
    do_rfc_stats();
    //dump_hash_stats();

    */
    printf("total size: %d\n\n", total_size);
}


// packet classification for packet[flow_id] in the flow trace
int flow_rfc(int flow_id)
{
    int		tid[MAXCHUNKS], cbm[MAXCHUNKS], chunk;
    uint16_t	rule;
    int		**p;

    /*
    // phase 0 table accesses
    p = phase_tables[0];
    tid[0] = flows[flow_id].sip >> shamt[0] & 0xFFFF;
    tid[1] = flows[flow_id].sip >> shamt[1] & 0xFFFF;
    tid[2] = flows[flow_id].dip >> shamt[2] & 0xFFFF;
    tid[3] = flows[flow_id].dip >> shamt[3] & 0xFFFF;
    tid[4] = flows[flow_id].proto >> shamt[4] & 0xFFFF;
    tid[5] = flows[flow_id].sp >> shamt[5] & 0xFFFF;
    tid[6] = flows[flow_id].dp >> shamt[6] & 0xFFFF;
    for (chunk = 0; chunk < MAXCHUNKS; chunk++) {
	cbm[chunk] = p[chunk][tid[chunk]];
	//dump_cbm_rules(&phase_cbms[0][chunk][cbm[chunk]]);
    }

    // phase 1 table accesses
    p = phase_tables[1];
    tid[0] = cbm[1] * num_cbms[0][0] + cbm[0];
    tid[1] = cbm[3] * num_cbms[0][2] + cbm[2];
    tid[2] = tid[4];
    tid[3] = cbm[6] * num_cbms[0][5] + cbm[5];
    cbm[0] = p[0][tid[0]];
    cbm[1] = p[1][tid[1]];
    cbm[2] = cbm[4];
    cbm[3] = p[2][tid[3]];

    // phase 2 table accesses
    p = phase_tables[2];
    tid[0] = cbm[0] * num_cbms[1][1] + cbm[1];
    tid[1] = cbm[2] * num_cbms[1][2] + cbm[3];
    cbm[0] = p[0][tid[0]];
    cbm[1] = p[1][tid[1]];


    // phase 3 table accesses
    p = phase_tables[3];
    tid[0] = cbm[0] * num_cbms[2][1] + cbm[1];
    cbm[0] = p[0][tid[0]];

    if (phase_cbms[3][0][cbm[0]].nrules > 0)
	rule = phase_cbms[3][0][cbm[0]].rules[0];
    else
	rule = numrules;
    */

    return rule;
}


// packet classifcation with a packet flow trace to check correctness of the rfc tables constructed
int run_rfc()
{
    int	    rule, i;

    for (i = 0; i < num_flows; i++) {
	rule = flow_rfc(i);
	if (rule != flows[i].match_rule) {
	    printf("Wrong match on flow[%d]: %u != %u\n", i, rule, flows[i].match_rule);
	    dump_one_flow(i);
	}
    }
}


int main(int argc, char* argv[])
{
    char *s = (char *)calloc(200, sizeof(char));

    parseargs(argc, argv);

    while(fgets(s, 200, fpr) != NULL) numrules++;
    rewind(fpr);

    free(s);

    // read rules
    ruleset = (pc_rule_t *) calloc(numrules, sizeof(pc_rule_t));
    numrules = loadrule(fpr, ruleset);
    printf("Number of rules: %d\n\n", numrules);

    if (func_read_flow) {
	// read in a flow trace for checking the correctness of the RFC constructed
	read_flow_trace(fpt);
	//dump_flows();
    }

    if (func_write_flow) {
	// generate a flow trace (used for checking the correctness of RFC packet classification)
	create_flows();
	write_flow_trace(fpt);
	fclose(fpt);
	//return 1;   // aim to produce trace, no need for packet classification
    }

    calc_ruleset_types();

    // constructing RFC tables
    construct_rfc();

    // check the correctness of RFC packet classification if a flow trace is provided
    if (func_read_flow)
	run_rfc();
}  
