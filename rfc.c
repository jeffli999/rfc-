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

block_table_t	*block_tables[PHASES][MAXCHUNKS];
// phase tables contaiting CBM ids for each chunk at each phase
int		*phase_tables[PHASES][MAXCHUNKS];
int		phase_table_sizes[PHASES][MAXCHUNKS];

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
int new_cbm(int phase, int chunk, uint16_t *rules, uint16_t nrules, int rulesum, int local)
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
    cbms[cbm_id].local = local;
    cbms[cbm_id].rulesum = rulesum;
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
int get_block_type(int *table, int b1, int b2, int n1, int n2)
{
    int	    i, j, base, offset, row, col, row_size, col_size, is_row_block, is_col_block, is_scalar_block;
    int	    block[BLOCKSIZE][BLOCKSIZE];

    row_size = (b1+1) * BLOCKSIZE > n1 ? n1 - b1*BLOCKSIZE : BLOCKSIZE;
    col_size = (b2+1) * BLOCKSIZE > n2 ? n2 - b2*BLOCKSIZE : BLOCKSIZE;
    row = b1 * BLOCKSIZE;
    col = b2 * BLOCKSIZE;
    base = row * n2;
    for (i = 0; i < row_size; i++) {
	offset = col;
	for (j = 0; j < col_size; j++) {
	    block[i][j] = table[base + offset++];
	}
	base += n2;
    }

    is_row_block = 1;
    for (i = 0; i < row_size-1; i++) {
	for (j = 0; j < col_size; j++) {
	    if (block[i][j] != block[i+1][j]) {
		is_row_block = 0;
		break;
	    }
	}
    }

    is_col_block = 1;
    for (j = 0; j < col_size-1; j++) {
	for (i = 0; i < row_size; i++) {
	    if (block[i][j] != block[i][j+1]) {
		is_col_block = 0;
		break;
	    }
	}
    }

    is_scalar_block = is_row_block && is_col_block;

    if (is_scalar_block)
	return POINT_BLOCK;

    if (is_row_block)
	return ROW_BLOCK;

    if (is_col_block)
	return COL_BLOCK;

    static int np2 = 0, np3 = 0;

    if (np2++ < 1000) {
	printf("block 2:\n");
	for (i = 0; i < row_size; i++) {
	    for (j = 0; j < col_size; j++) {
		printf("%4d ", block[i][j]);
	    }
	    printf("\n");
	}
    }

    if (table == phase_tables[3][0]) {
	if (np3++ < 1000) {
	    printf("block 3:\n");
	    for (i = 0; i < row_size; i++) {
		for (j = 0; j < col_size; j++) {
		    printf("%4d ", block[i][j]);
		}
		printf("\n");
	    }
	}
    }

    return MATRIX_BLOCK;
}


// for block type statistics on the original phase table scheme
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


// dump out the rulelist of the CBM
void dump_cbm_rules(cbm_t *cbm)
{
    uint16_t	i;

    printf("cbm[%d]: ", cbm->id);
    for (i = 0; i < cbm->nrules; i++)
	printf("%u ", cbm->rules[i]);
    printf("\n");
}


// a CBM is the local type if it contains a rule that only appears in this CBM
int is_cbm_local(int phase, int chunk, uint16_t rule)
{
    int		f, local;

    switch (phase) {
    case 0:
	f = chunk_to_field[chunk];
	local = rule_types[f][rule];
	break;
    case 1:
	if (chunk == 0) {   // SIP
	    local = rule_types[0][rule];
	} else if (chunk == 1) {    // DIP
	    local = rule_types[1][rule];
	} else {    // DP x SP
	    local = rule_types[4][rule] && rule_types[3][rule];
	}
	break;
    case 2:
	if (chunk == 0) {   // SIP x DIP
	    local = rule_types[0][rule] && rule_types[1][rule];
	} else {    // PROTO x (DP x SP)
	    local = rule_types[2][rule] && rule_types[4][rule] && rule_types[3][rule];
	}
	break;
    case 3:
	local = rule_types[0][rule] && rule_types[1][rule] && rule_types[2][rule]
	    && rule_types[3][rule] && rule_types[4][rule];
	break;
    default:
	break;
    }

    return local;
}


// intersecting rulelists of two phase-1 CBMs
int cbm_intersect(int phase, int chunk, uint16_t *rules, int *rulesum, int *local, 
	int ph1, int ch1, int id1, int ph2, int ch2, int id2)
{
    cbm_t	*c1 = &phase_cbms[ph1][ch1][id1], *c2 = &phase_cbms[ph2][ch2][id2];
    int		n = 0, ncmp = 0;
    uint16_t	i = 0, j = 0, rule;

    *rulesum = 0;
    *local = 0;
    while (i < c1->nrules && j < c2->nrules) {
	if (c1->rules[i] == c2->rules[j]) {
	    rule = c1->rules[i];
	    rules[n++] = rule;
	    *rulesum += rule;
	    if (*local != POINT_LOCAL) {
		if (is_cbm_local(phase, chunk, rule)) {
		    *local = POINT_LOCAL;
		} else {
		    if (is_cbm_local(ph1, ch1, rule))
			*local |= 2;
		    if (is_cbm_local(ph2, ch2, rule))
			*local |= 1;
		}
	    }
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
    int		rulesum, point, next_point, cbm_id, i, j, table_size = 65536, local;


    phase_table_sizes[0][chunk] = table_size;
    phase_tables[0][chunk] = (int *) calloc(table_size, sizeof(int));

    init_cbm_hash();

    for (i = 0; i < num_epoints[chunk]; i++) {
	// 1. Collect rules covering an end-point, then create a CBM or match an existing CBM for it
	point = epoints[chunk][i];
	nrules = collect_epoint_rules(chunk, point, rules, &rulesum);
	cbm_id = cbm_lookup(rules, nrules, rulesum, phase_cbms[0][chunk]);
	if (cbm_id < 0)
	    cbm_id = new_cbm(0, chunk, rules, nrules, rulesum, local);
	phase_tables[0][chunk][point] = cbm_id;

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
	    cbm_id = new_cbm(0, chunk, rules, nrules, rulesum, local);
	for (j = point+1; j < next_point; j++) {
	    phase_tables[0][chunk][j] = cbm_id;
	}
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
	//do_cbm_stats(0, chunk, 0);
    }
    //dump_intersect_stats();
    bzero(intersect_stats, MAXRULES*2*sizeof(long));
}



//--------------------------------------------------------------------------------------------------
// Section: crossproduct phase functions
//--------------------------------------------------------------------------------------------------

int local_counts[4];

int crossprod_block(int phase, int chunk, int ph1, int ch1, int ph2, int ch2, int b1, int b2, int n1, int n2)
{
    int		start1, end1, start2, end2, i, j, rulesum, cbm_id, local; 
    uint16_t	rules[MAXRULES], nrules;
    cbm_t	*cbms1, *cbms2;

    start1 = b1 * BLOCKSIZE;
    end1 = (b1 + 1) * BLOCKSIZE;
    if (end1 > n1)
	end1 = n1;
    start2 = b2 * BLOCKSIZE;
    end2 = (b2 + 1) * BLOCKSIZE;
    if (end2 > n2)
	end2 = n2;

    cbms1 = phase_cbms[ph1][ch1];
    cbms2 = phase_cbms[ph2][ch2];

    //printf("**b%dxb%d**\n", b1, b2);
    for (i = start1; i < end1; i++) {
	for (j = start2; j < end2; j++) {
	    nrules = cbm_intersect(phase, chunk, rules, &rulesum, &local, ph1, ch1, i, ph2, ch2, j);
	    cbm_id = cbm_lookup(rules, nrules, rulesum, phase_cbms[phase][chunk]);
	    if (cbm_id < 0)
		cbm_id = new_cbm(phase, chunk, rules, nrules, rulesum, local);
	    else if (phase == 2 && local == 3)
		printf("[%d, %d] = %d\n", i, j, cbm_id);
	    
	    local_counts[local]++;

	    //if (phase == 2 && local == POINT_LOCAL)
	//	printf("[%d, %d] = %d\n", i, j, cbm_id);
	}
    }
}


// for chunks with both major & minor rule sets (SIP & DIP chunks)
int crossprod_chunks(int phase, int chunk)
{
    int	    ph1, ph2, ch1, ch2, n1, n2, nb1, nb2, i, j, nlocals[4];

    init_cbm_hash();

    local_counts[0] = local_counts[1] = local_counts[2] = local_counts[3] = 0; 

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
	    ph1 = 0;
	    ch1 = 4; ch2 = 2;
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
	for (j = 0; j < nb2; j++) {
	    crossprod_block(phase, chunk, ph1, ch1, ph2, ch2, i, j, n1, n2);
	}
    }

    free_cbm_hash();

    for (i = 0; i < 4; i++) 
	nlocals[i] = 0;
    for (i = 0; i < num_cbms[phase][chunk]; i++) {
	nlocals[phase_cbms[phase][chunk][i].local]++;
    }
    printf("Chunk[%d]: %d CBMs; locals: [%d/%d, %d/%d, %d/%d, %d/%d]\n", chunk, num_cbms[phase][chunk], 
	    nlocals[0], local_counts[0], nlocals[1], local_counts[1], 
	    nlocals[2], local_counts[2], nlocals[3], local_counts[3]);
}


// do phase 1 crossproducting for three pairs of chunks in phase 0,
// Alert 1: the protocol chunk is left for crossproducting in next phase
// Alert 2: be careful of the order of crosspoducting for each pair of chunks (as commented in below code)
int p1_crossprod()
{

    // SIP[31:16] x SIP[15:0]
    crossprod_chunks(1, 0);

    // DIP[31:16] x DIP[15:0]
    crossprod_chunks(1, 1);

    // DP x SP
    crossprod_chunks(1, 2);

    bzero(intersect_stats, MAXRULES*2*sizeof(long));
}


// do phase 2 crossproducting for two pairs of chunks,
// Alert: three chunks (SIP, DIP, Ports) are from phase 1, and one chunk (protocol field) from phase 0.
// Alert: pay attention of their orders in crossproducting
int p2_crossprod()
{
    // SIP x DIP
    crossprod_chunks(2, 0);

    // PROTO x (DP x SP)
    crossprod_chunks(2, 1);

    bzero(intersect_stats, MAXRULES*2*sizeof(long));
}


int p3_crossprod()
{
    crossprod_chunks(3, 0);

}


/*
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
    crossprod_2chunk(2, 0, cbms1, n1, cbms2, n2, rest_fields);
    printf("Chunk[%d]: %d CBMs in Table[%d]\n", 0, num_cbms[2][0], table_size);
    do_cbm_stats(2, 0, 0);
    //table_row_run(phase_tables[2][0], n1, n2);
    //table_column_run(phase_tables[2][0], n1, n2);
    table_block_stats(phase_tables[2][0], n1, n2);
    cbm_minor_stats(0);
    cbm_minor_stats(1);

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
    crossprod_2chunk(2, 1, cbms1, n1, cbms2, n2, rest_fields);
    printf("Chunk[%d]: %d CBMs in Table[%d]\n", 0, num_cbms[2][1], table_size);
    do_cbm_stats(2, 1, 0);

    //dump_intersect_stats();
    bzero(intersect_stats, MAXRULES*2*sizeof(long));
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
    crossprod_2chunk(3, 0, cbms1, n1, cbms2, n2, rest_fields);
    printf("Chunk[%d]: %d CBMs in Table[%d]\n", 0, num_cbms[3][0], table_size);
    do_cbm_stats(3, 0, 0);
    table_block_stats(phase_tables[3][0], n1, n2);

    //dump_intersect_stats();
}
*/


// statistics on the sizes of CBM sets and phase tables
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
/*
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
*/
}


// constructing the RFC tables with a 3-phase process
void construct_rfc()
{
    clock_t t;

    gen_endpoints();
    dump_endpoints();

    t = clock();
    gen_p0_tables();
    printf("***Phase 0 spent %lds\n\n", (clock()-t)/1000000);

    t = clock();
    p1_crossprod();
    printf("***Phase 1 spent %lds\n\n", (clock()-t)/1000000);

    t = clock();
    p2_crossprod();
    printf("***Phase 2 spent %lds\n\n", (clock()-t)/1000000);

    t = clock();
    p3_crossprod();
    printf("***Phase 3 spent %lds\n\n", (clock()-t)/1000000);

    /*
    do_rfc_stats();
    //dump_hash_stats();

    */
    printf("\n");
}


// packet classification for packet[flow_id] in the flow trace
int flow_rfc(int flow_id)
{
    int		tid[MAXCHUNKS], cbm[MAXCHUNKS], chunk;
    uint16_t	rule;
    int		**p;

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
