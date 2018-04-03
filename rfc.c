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
block_entry_t	    *block_entry_tables[PHASES][MAXCHUNKS];
int		    block_table_sizes[PHASES][MAXCHUNKS];
array_block_t	    *row_block_tables[PHASES][MAXCHUNKS];
int		    row_table_sizes[PHASES][MAXCHUNKS];
array_block_t	    *col_block_tables[PHASES][MAXCHUNKS];
int		    col_table_sizes[PHASES][MAXCHUNKS];
matrix16_block_t    *matrix16_block_tables[PHASES][MAXCHUNKS];
int		    matrix16_table_sizes[PHASES][MAXCHUNKS];
matrix32_block_t    *matrix32_block_tables[PHASES][MAXCHUNKS];
int		    matrix32_table_sizes[PHASES][MAXCHUNKS];
matrix48_block_t    *matrix48_block_tables[PHASES][MAXCHUNKS];
int		    matrix48_table_sizes[PHASES][MAXCHUNKS];
matrix_block_t	    *matrix_block_tables[PHASES][MAXCHUNKS];
int		    matrix_table_sizes[PHASES][MAXCHUNKS];

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

int	total_table_size, total_block_table_size;



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
    cbms[cbm_id].scan_chunk = 0;
    cbms[cbm_id].scan_cbm = -1;
    cbms[cbm_id].scan_count = 0;
    cbms[cbm_id].density = 0;
    cbms[cbm_id].order = 0;
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
	    // 5.1 statistics on #runs in a row for deciding cbms1 shuffling
	    if (cbm_id != cbm_id0) {
		cbms1[i].run++;
		cbm_id0 = cbm_id;
	    }
	    // 5.2 statsitcs on its counts in the phase table
	    //phase_cbms[phase][chunk][cbm_id].count++;
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
    total_table_size = 65536 * 7 * sizeof(int);
    //dump_intersect_stats();
    bzero(intersect_stats, MAXRULES*2*sizeof(long));
}



//--------------------------------------------------------------------------------------------------
// Section: crossproduct phase functions
//--------------------------------------------------------------------------------------------------


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


void new_block_entry(int phase, int chunk, int block_type)
{
    int		    n = block_table_sizes[phase][chunk];
    block_entry_t   *table = block_entry_tables[phase][chunk];

    if ((n & 0xFF) == 0)
	table = realloc(table, (n + 0x100) * sizeof(block_entry_t));

    table[n].type = block_type;
    switch (block_type) {
    case ROW_BLOCK:
	table[n].id = row_table_sizes[phase][chunk];
	break;
    case COL_BLOCK:
	table[n].id = col_table_sizes[phase][chunk];
	break;
    default:	    // MATRIX_BLOCK
	table[n].id = matrix_table_sizes[phase][chunk];
	break;
    }

    block_table_sizes[phase][chunk]++;
    block_entry_tables[phase][chunk] = table;
}


void set_matrix16_map(uint8_t *map, int row, int col, int id)
{
    int	    base = (row * BLOCKSIZE + col) >> 1;
    int	    offset = ((row * BLOCKSIZE + col) & 0x1) << 2;
    uint8_t val = id << offset;

    map[base] &= 0xFF - (0xF << offset);
    map[base] |= val;
}


int new_matrix16_block(int phase, int chunk, int block[][BLOCKSIZE], int row_size, int col_size, int *cbms, int n)
{
    int		    table_size = matrix16_table_sizes[phase][chunk], i, j, k;
    matrix16_block_t *table = matrix16_block_tables[phase][chunk];

    if ((table_size & 0xFF) == 0)
	table = realloc(table, (table_size + 0x100) * sizeof(matrix16_block_t));

    table[table_size].row_size = row_size;
    table[table_size].col_size = col_size;
    for (i = 0; i < row_size; i++) {
	for (j = 0; j < col_size; j++) {
	    for (k = 0; k < n; k++) {
		if (block[i][j] == cbms[k]) {
		    set_matrix16_map(table[table_size].map, i, j, k);
		    break;
		}
	    }
	    if (k == n) {
		fprintf(stderr, "Panic: fail to match cbm for creating matrix_block16[%d]!\n", table_size);
		exit(1);
	    }
	}
    }
    memcpy(table[table_size].cbms, cbms, 16*sizeof(int));

    matrix16_table_sizes[phase][chunk]++;
    matrix16_block_tables[phase][chunk] = table;
}


void set_matrix32_map(uint8_t *map, int row, int col, int id)
{
    int	    base = (row * BLOCKSIZE + col) >> 1;
    int	    offset = ((row * BLOCKSIZE + col) & 0x1) << 2;
    uint8_t val = id << offset;

    map[base] &= 0xFF - (0xF << offset);
    map[base] |= val;
}


int new_matrix32_block(int phase, int chunk, int block[][BLOCKSIZE], int row_size, int col_size, int *cbms, int n)
{
    int			table_size = matrix32_table_sizes[phase][chunk], i, j, k;
    matrix32_block_t	*table = matrix32_block_tables[phase][chunk];

    if ((table_size & 0xFF) == 0)
	table = realloc(table, (table_size + 0x100) * sizeof(matrix32_block_t));

    table[table_size].row_size = row_size;
    table[table_size].col_size = col_size;
    for (i = 0; i < row_size; i++) {
	for (j = 0; j < col_size; j++) {
	    for (k = 0; k < n; k++) {
		if (block[i][j] == cbms[k]) {
		    set_matrix32_map(table[table_size].map, i, j, k);
		    break;
		}
	    }
	    if (k == n) {
		fprintf(stderr, "Panic: fail to match cbm for creating matrix_block32[%d]!\n", table_size);
		exit(1);
	    }
	}
    }
    memcpy(table[table_size].cbms, cbms, 32*sizeof(int));

    matrix32_table_sizes[phase][chunk]++;
    matrix32_block_tables[phase][chunk] = table;
}


void set_matrix48_map(uint8_t *map, int row, int col, int id)
{
    int	    base = (row * BLOCKSIZE + col) >> 1;
    int	    offset = ((row * BLOCKSIZE + col) & 0x1) << 2;
    uint8_t val = id << offset;

    map[base] &= 0xFF - (0xF << offset);
    map[base] |= val;
}


int new_matrix48_block(int phase, int chunk, int block[][BLOCKSIZE], int row_size, int col_size, int *cbms, int n)
{
    int		    table_size = matrix48_table_sizes[phase][chunk], i, j, k;
    matrix48_block_t *table = matrix48_block_tables[phase][chunk];

    if ((table_size & 0xFF) == 0)
	table = realloc(table, (table_size + 0x100) * sizeof(matrix48_block_t));

    table[table_size].row_size = row_size;
    table[table_size].col_size = col_size;
    for (i = 0; i < row_size; i++) {
	for (j = 0; j < col_size; j++) {
	    for (k = 0; k < n; k++) {
		if (block[i][j] == cbms[k]) {
		    set_matrix48_map(table[table_size].map, i, j, k);
		    break;
		}
	    }
	    if (k == n) {
		fprintf(stderr, "Panic: fail to match cbm for creating matrix_block48[%d]!\n", table_size);
		exit(1);
	    }
	}
    }
    memcpy(table[table_size].cbms, cbms, 48*sizeof(int));

    matrix48_table_sizes[phase][chunk]++;
    matrix48_block_tables[phase][chunk] = table;
}


int new_matrix_block(int phase, int chunk, int block[][BLOCKSIZE], int row_size, int col_size, int *cbms)
{
    int			table_size = matrix_table_sizes[phase][chunk], i, j;
    matrix_block_t	*table = matrix_block_tables[phase][chunk];

    if ((table_size & 0xFF) == 0)
	table = realloc(table, (table_size + 0x100) * sizeof(matrix_block_t));

    table[table_size].row_size = row_size;
    table[table_size].col_size = col_size;
    for (i = 0; i < row_size; i++) {
	for (j = 0; j < col_size; j++) {
	    table[table_size].cbms[i][j] = block[i][j];
	}
    }

    matrix_table_sizes[phase][chunk]++;
    matrix_block_tables[phase][chunk] = table;
}


// return number of different points in a block
int scan_matrix(int phase, int chunk, int block[][BLOCKSIZE], int row_size, int col_size)
{
    int	    i, j, k, n = 1, block_type;
    int	    cbms[BLOCKSIZE*BLOCKSIZE];

    cbms[0] = block[0][0];
    for (i = 0; i < row_size; i++) {
	for (j = 0; j < col_size; j++) {
	    for (k = 0; k < n; k++) {
		if (cbms[k] == block[i][j])
		    break;
	    }
	    if (k == n) {
		cbms[n++] = block[i][j];
	    }
	}
    }

    if (n <= 16) {
	block_type = MATRIX16_BLOCK;
	new_block_entry(phase, chunk, block_type);
	new_matrix16_block(phase, chunk, block, row_size, col_size, cbms, n);
    } else if (n <= 32) {
	block_type = MATRIX32_BLOCK;
	new_block_entry(phase, chunk, block_type);
	new_matrix32_block(phase, chunk, block, row_size, col_size, cbms, n);
    } else if (n <= 48) {
	block_type = MATRIX48_BLOCK;
	new_block_entry(phase, chunk, block_type);
	new_matrix48_block(phase, chunk, block, row_size, col_size, cbms, n);
    } else {
	block_type = MATRIX_BLOCK;
	new_block_entry(phase, chunk, block_type);
	new_matrix_block(phase, chunk, block, row_size, col_size, cbms);
    }

    return block_type;
}


void set_row_map(uint8_t *map, int row, int col, int id)
{
    int	    base = (row * BLOCKSIZE + col) >> 3;
    int	    offset = (row * BLOCKSIZE + col) & 0x7;
    uint8_t val = id << offset;

    map[base] &= 0xFF - (1 << offset);
    map[base] |= val;
}


// Scan a row in a block to get the prime CBM in this row. Return 1 if success, otherwise return 0
int scan_one_row(int block[][BLOCKSIZE], int row, int col_size, array_block_t *row_block)
{
    int	    i, id, n = 1;
    int	    *cbms = row_block->cbms;
    uint8_t *map = row_block->map;

    cbms[row] = block[row][0];
    set_row_map(map, row, 0, 0);
    for (i = 1; i < col_size; i++) {
	if (block[row][i] == cbms[row]) {
	    id = 0;
	} else if (n == 1) {
	    cbms[BLOCKSIZE+row] = block[row][i];
	    n = 2;
	    id = 1;
	} else if (block[row][i] == cbms[BLOCKSIZE+row]) {
	    id = 1;
	} else
	    return 0;

	set_row_map(map, row, i, id);
    }

    return 1;
}


void new_array_block(int phase, int chunk, array_block_t *block, int row_size, int col_size, int block_type)
{
    int		    n, i;
    array_block_t   *table;

    new_block_entry(phase, chunk, block_type);

    if (block_type == ROW_BLOCK) {
	n = row_table_sizes[phase][chunk];
	table = row_block_tables[phase][chunk];
    } else {
	n = col_table_sizes[phase][chunk];
	table = col_block_tables[phase][chunk];
    }

    if ((n & 0xFF) == 0)
	table = realloc(table, (n + 0x100) * sizeof(array_block_t));

    table[n].row_size = row_size;
    table[n].col_size = col_size;
    memcpy(table[n].map, block->map, BLOCKSIZE*BLOCKSIZE >> 3);
    memcpy(table[n].cbms, block->cbms, BLOCKSIZE*2*sizeof(int));

    if (block_type == ROW_BLOCK) {
	row_table_sizes[phase][chunk]++;
	row_block_tables[phase][chunk] = table;
    } else {
	col_table_sizes[phase][chunk]++;
	col_block_tables[phase][chunk] = table;
    }
}


// return 1 if it is a row block, otherwise return 0
int scan_rows(int phase, int chunk, int block[][BLOCKSIZE], int row_size, int col_size)
{
    int		    i, good_row;
    array_block_t   row_block;

    for (i = 0; i < row_size; i++) {
	good_row = scan_one_row(block, i, col_size, &row_block);
	if (!good_row)
	    return 0;		// not a row block
    }
    
    new_array_block(phase, chunk, &row_block, row_size, col_size, ROW_BLOCK);
    return 1;
}


void set_col_map(uint8_t *map, int row, int col, int id)
{
    int	    base = (col * BLOCKSIZE + row) >> 3;
    int	    offset = (col * BLOCKSIZE + row) & 0x7;
    uint8_t val = id << offset;

    map[base] &= 0xFF - (1 << offset);
    map[base] |= val;
}


// Scan a row in a block to get the prime CBM in this row. Return 1 if success, otherwise return 0
int scan_one_col(int block[][BLOCKSIZE], int col, int row_size, array_block_t *col_block)
{
    int	    i, id, n = 1;
    int	    *cbms = col_block->cbms;
    uint8_t *map = col_block->map;

    cbms[col] = block[0][col];
    set_col_map(map, col, 0, 0);
    for (i = 1; i < row_size; i++) {
	if (block[i][col] == cbms[col]) {
	    id = 0;
	} else if (n == 1) {
	    cbms[BLOCKSIZE+col] = block[i][col];
	    n = 2;
	    id = 1;
	} else if (block[i][col] == cbms[BLOCKSIZE+col]) {
	    id = 1;
	} else
	    return 0;

	set_col_map(map, i, col, id);
    }

    return 1;
}


// return 1 if it is a col block, otherwise return 0
int scan_cols(int phase, int chunk, int block[][BLOCKSIZE], int row_size, int col_size)
{
    int		    i, good_col;
    array_block_t   col_block;

    for (i = 0; i < col_size; i++) {
	good_col = scan_one_col(block, i, row_size, &col_block);
	if (!good_col)
	    return 0;		// not a col block
    }
    
    new_array_block(phase, chunk, &col_block, row_size, col_size, COL_BLOCK);
    return 1;
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


int add_block(int phase, int chunk, int b1, int b2, int block[][BLOCKSIZE], int row_size, int col_size)
{
    int		success, block_type = MATRIX_BLOCK;

    success = scan_rows(phase, chunk, block, row_size, col_size);
    if (success) return ROW_BLOCK;

    success = scan_cols(phase, chunk, block, row_size, col_size);
    if (success) return COL_BLOCK;

    block_type = scan_matrix(phase, chunk, block, row_size, col_size);

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
    int	    n, table_size, total_size;
    block_entry_t   *table = block_entry_tables[phase][chunk];

    n = block_table_sizes[phase][chunk];
    table_size = block_table_sizes[phase][chunk] * sizeof(block_entry_t);
    printf("block_table[%4d]:\t%d bytes\n", n, table_size);
    total_size = table_size;

    n = row_table_sizes[phase][chunk];
    table_size = n * ARRAY_BLOCK_SIZE;
    printf("ROW_BLOCK[%4d]:\t%d bytes\n", n, table_size);
    total_size += table_size;

    n = col_table_sizes[phase][chunk];
    table_size = n * ARRAY_BLOCK_SIZE;
    printf("COL_BLOCK[%4d]:\t%d bytes\n", n, table_size);
    total_size += table_size;

    n = matrix16_table_sizes[phase][chunk];
    table_size = n * MATRIX16_BLOCK_SIZE;
    printf("MATRIX16_BLOCK[%4d]:\t%d bytes\n", n, table_size);
    total_size += table_size;

    n = matrix32_table_sizes[phase][chunk];
    table_size = n * MATRIX32_BLOCK_SIZE;
    printf("MATRIX32_BLOCK[%4d]:\t%d bytes\n", n, table_size);
    total_size += table_size;

    n = matrix48_table_sizes[phase][chunk];
    table_size = n * MATRIX48_BLOCK_SIZE;
    printf("MATRIX48_BLOCK[%4d]:\t%d bytes\n", n, table_size);
    total_size += table_size;

    n = matrix_table_sizes[phase][chunk];
    table_size = n * MATRIX_BLOCK_SIZE;
    printf("MATRIX_BLOCK[%4d]:\t%d bytes\n", n, table_size);
    total_size += table_size;

    printf("Chunk total size:\t%d bytes\n\n", total_size);

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


static int cbm_density_cmp(const void *p, const void *q)
{
    if (((cbm_t *)q)->density > ((cbm_t *)p)->density)
	return 1;
    else if (((cbm_t *)q)->density < ((cbm_t *)p)->density)                                                   
	return -1;                                                     
    else
	return 0;                                                                                   
}


static int cbm_order_cmp(const void *p, const void *q)
{
    if (((cbm_t *)q)->order > ((cbm_t *)p)->order)
	return 1;
    else if (((cbm_t *)q)->order < ((cbm_t *)p)->order)                                                   
	return -1;                                                     
    else
	return 0;                                                                                   
}


void scan_cbm2(int phase, int chunk, int ph1, int ch1, int ph2, int ch2, int cbm1_id)
{
    int		i, cbm_id, count, n1 = num_cbms[ph1][ch1], n2 = num_cbms[ph2][ch2];
    cbm_t	*cbms = phase_cbms[phase][chunk];
    int		*table = phase_tables[phase][chunk];

    for (i = 0; i < n2; i++) {
	cbm_id = table[cbm1_id*n2 + i];
	if (cbms[cbm_id].scan_chunk == 1 && cbms[cbm_id].scan_cbm == cbm1_id)
	    cbms[cbm_id].scan_count++;
	else {
	    cbms[cbm_id].scan_chunk = 1;
	    cbms[cbm_id].scan_cbm = cbm1_id;
	    cbms[cbm_id].scan_count = 1;
	}
    }

    for (i = 0; i < n2; i++) {
	cbm_id = table[cbm1_id*n2 + i];
	count = cbms[cbm_id].scan_count;
	phase_cbms[ph2][ch2][i].density += count;
    }
}


void scan_cbm1(int phase, int chunk, int ph1, int ch1, int ph2, int ch2, int cbm2_id)
{
    int		i, base, cbm_id, count, n1 = num_cbms[ph1][ch1], n2 = num_cbms[ph2][ch2];
    cbm_t	*cbms = phase_cbms[phase][chunk];
    int		*table = phase_tables[phase][chunk];

    for (i = 0; i < n1; i++) {
	cbm_id = table[i*n2 + cbm2_id];
	if (cbms[cbm_id].scan_chunk == 2 && cbms[cbm_id].scan_cbm == cbm2_id)
	    cbms[cbm_id].scan_count++;
	else {
	    cbms[cbm_id].scan_chunk = 2;
	    cbms[cbm_id].scan_cbm = cbm2_id;
	    cbms[cbm_id].scan_count = 1;
	}
    }

    for (i = 0; i < n1; i++) {
	cbm_id = table[i*n2 + cbm2_id];
	count = cbms[cbm_id].scan_count;
	phase_cbms[ph1][ch1][i].density += count;
    }
}


static int id_count_cmp(const void *p, const void *q)
{
    if (((id_count_t *)p)->count > ((id_count_t *)q)->count)
	return 1;
    else if (((id_count_t *)p)->count < ((id_count_t *)q)->count)
	return -1;                                                     
    else
	return 0;                                                                                   
}


void scan_test(int phase, int chunk, int ph1, int ch1, int ph2, int ch2, int cbm2_id)
{
    int	    i, n = num_cbms[ph1][ch1], cbm_id;
    id_count_t	*cbm_counts;
    uint64_t	order;

    cbm_counts = calloc(num_cbms[phase][chunk], sizeof(id_count_t));

    for (i = 0; i < num_cbms[ph1][ch1]; i++) {
	cbm_id = phase_tables[phase][chunk][i*num_cbms[ph2][ch2] + cbm2_id];
	cbm_counts[cbm_id].id = cbm_id;
	cbm_counts[cbm_id].count++;
    }
    qsort(cbm_counts, num_cbms[phase][chunk], sizeof(id_count_t), id_count_cmp);

    order = 100000;
    for (i = num_cbms[phase][chunk]-1; i >= 0; i--) {
	if (cbm_counts[i].count == 0)
	    break;
	cbm_id = cbm_counts[i].id;
	phase_cbms[phase][chunk][cbm_id].order = order--;
    }

    for (i = 0; i < n; i++) {
	cbm_id = phase_tables[phase][chunk][i*num_cbms[ph2][ch2] + cbm2_id];
	order = phase_cbms[phase][chunk][cbm_id].order;
	phase_cbms[ph1][ch1][i].order = order;
    }

    qsort(phase_cbms[ph1][ch1], num_cbms[ph1][ch1], sizeof(cbm_t), cbm_order_cmp);

    free(cbm_counts);
}


void scan_crossprod_cbm(int phase, int chunk)
{
    int	    i, n = num_cbms[phase][chunk], cbm_id;
    id_count_t	*cbm_counts;
    uint64_t	order;

    cbm_counts = calloc(n, sizeof(id_count_t));

    for (i = 0; i < phase_table_sizes[phase][chunk]; i++) {
	cbm_id = phase_tables[phase][chunk][i];
	cbm_counts[cbm_id].id = cbm_id;
	cbm_counts[cbm_id].count++;
    }

    qsort(cbm_counts, n, sizeof(int), id_count_cmp);
    for (i = 0; i < n; i++)
	printf("cbm_count[%d]: %d\n", cbm_counts[i].id, cbm_counts[i].count);

    order = 0x1;
    for (i = n-1; i < n; i++) {
	cbm_id = cbm_counts[i].id;
	phase_cbms[phase][chunk][cbm_id].order = order;
	order <<= 1;
    }

    free(cbm_counts);
}


void update_cbm_runs(int phase, int chunk, int ph1, int ch1, int ph2, int ch2)
{
    int		i, j, n1 = num_cbms[ph1][ch1], n2 = num_cbms[ph2][ch2];
    int		cbm_id0, cbm_id, cbm1_id, cbm2_id;
    cbm_t	*cbms1 = phase_cbms[ph1][ch1], *cbms2 = phase_cbms[ph2][ch2];
    int		*table = phase_tables[phase][chunk];

    for (i = 0; i < n1; i++) {
	cbm_id0 = -1;
	cbm1_id = cbms1[i].id;
	cbms1[i].run = 0;
	for (j = 0; j < n2; j++) {
	    cbm2_id = cbms2[j].id;
	    cbm_id = table[cbm1_id*n2 + cbm2_id];
	    if (cbm_id != cbm_id0) {
		cbms1[i].run++;
		cbm_id0 = cbm_id;
	    }
	}
    }

    for (j = 0; j < n2; j++) {
	cbm_id0 = -1;
	cbm2_id = cbms2[j].id;
	cbms2[j].run = 0;
	for (i = 0; i < n1; i++) {
	    cbm1_id = cbms1[i].id;
	    cbm_id = phase_tables[phase][chunk][cbm1_id*n2 + cbm2_id];
	    if (cbm_id != cbm_id0) {
		cbms2[j].run++;
		cbm_id0 = cbm_id;
	    }
	}
    }
}


void sort_cbms_by_order(int phase, int chunk, int ph1, int ch1, int ph2, int ch2)
{
    int		i, j, base, cbm_id, n1 = num_cbms[ph1][ch1], n2 = num_cbms[ph2][ch2];
    uint64_t	order;

    scan_crossprod_cbm(phase, chunk);
    for (i = 0; i < n1; i++) {
	base = i * n2;
	for (j = 0; j < n2; j++) {
	    cbm_id = phase_tables[phase][chunk][base+j];
	    order = phase_cbms[phase][chunk][cbm_id].order;
	    phase_cbms[ph1][ch1][i].order |= order;
	    phase_cbms[ph2][ch2][j].order |= order;
	}
    }

    qsort(phase_cbms[ph1][ch1], num_cbms[ph1][ch1], sizeof(cbm_t), cbm_order_cmp);
    qsort(phase_cbms[ph2][ch2], num_cbms[ph2][ch2], sizeof(cbm_t), cbm_order_cmp);
}


void sort_cbms_by_density(int phase, int chunk, int ph1, int ch1, int ph2, int ch2)
{
    int		i, j, base, cbm_id, count, n1 = num_cbms[ph1][ch1], n2 = num_cbms[ph2][ch2];

    for (i = 0; i < n1; i++)
	scan_cbm2(phase, chunk, ph1, ch1, ph2, ch2, i);

    for (i = 0; i < n2; i++)
	scan_cbm1(phase, chunk, ph1, ch1, ph2, ch2, i);

    qsort(phase_cbms[ph1][ch1], num_cbms[ph1][ch1], sizeof(cbm_t), cbm_density_cmp);
    qsort(phase_cbms[ph2][ch2], num_cbms[ph2][ch2], sizeof(cbm_t), cbm_density_cmp);
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

    total_table_size += phase_table_sizes[1][0];

    sort_cbms_by_density(1, 0, 0, 1, 0, 0);
    //sort_cbms_by_density(1, 0, 0, 1, 0, 0);
    total_block_table_size += construct_block_tables(1, 0);

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

    total_table_size += phase_table_sizes[1][1];

    sort_cbms_by_density(1, 1, 0, 3, 0, 2);
    total_block_table_size += construct_block_tables(1, 1);

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

    total_table_size += phase_table_sizes[1][2];

    sort_cbms_by_density(1, 2, 0, 6, 0, 5);
    total_block_table_size += construct_block_tables(1, 2);

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

    total_table_size += phase_table_sizes[2][0];

    sort_cbms_by_density(2, 0, 1, 0, 1, 1);
    total_block_table_size += construct_block_tables(2, 0);

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

    total_table_size += phase_table_sizes[2][1];

    sort_cbms_by_density(2, 1, 0, 4, 1, 2);
    total_block_table_size += construct_block_tables(2, 1);

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

    total_table_size += phase_table_sizes[3][0];

    /*
    for (i = 0; i < num_cbms[2][0]; i++)
	phase_cbms[2][0][i].run >>= 2;
    for (i = 0; i < num_cbms[2][1]; i++)
	phase_cbms[2][1][i].run >>= 8;

    for (i = 0; i < n2; i++) {
	printf("table column[%d]\n", i);
	dump_table_column(3, 0, n1, n2, i);
    }
    dump_cbm_runs(2, 0);
    dump_cbm_runs(2, 1);
    sort_cbms_by_run(2, 0);
    sort_cbms_by_run(2, 1);
    printf("After sorting...\n");
    dump_cbm_runs(2, 0);
    dump_cbm_runs(2, 1);
    */

    dump_cbm_runs(2, 0);
    dump_cbm_runs(2, 1);
    
    scan_test(3, 0, 2, 0, 2, 1, 0);
    //sort_cbms_by_order(3, 0, 2, 0, 2, 1);
    //sort_cbms_by_density(3, 0, 2, 0, 2, 1);
    update_cbm_runs(3, 0, 2, 0, 2, 1);
    sort_cbms_by_run(2, 1);
    total_block_table_size += construct_block_tables(3, 0);
    printf("After sorting...\n");
    dump_cbm_runs(2, 0);
    dump_cbm_runs(2, 1);

    /*
    matrix_block_t  *table = matrix_block_tables[3][0];
    for (i = 0; i < matrix_table_sizes[3][0]; i++) {
	printf("matrix[%d]\n", i);
	dump_matrix_block(3, 0, i);
    }
    */

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
    clock_t t;

    gen_endpoints();
    dump_endpoints();

    t = clock();
    gen_p0_tables();
    total_table_size = 65536 * 7 * sizeof(int);
    total_block_table_size = 65536 * 7 * sizeof(int);
    printf("***** Phase 0 spent %lds *****\n\n", (clock()-t)/1000000);

    t = clock();
    p1_crossprod();
    printf("***** Phase 1 spent %lds *****\n\n", (clock()-t)/1000000);

    t = clock();
    p2_crossprod();
    printf("***** Phase 2 spent %lds *****\n\n", (clock()-t)/1000000);

    t = clock();
    p3_crossprod();
    printf("***** Phase 3 spent %lds *****\n\n", (clock()-t)/1000000);

    /*
    do_rfc_stats();
    //dump_hash_stats();

    */
    total_table_size <<= 2;
    printf("Base table size:  %9d\n", total_table_size);
    printf("Block table size: %9d\n", total_block_table_size);
    printf("Compression ratio: %.1f\n\n", (double) total_table_size / (double) total_block_table_size);
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
