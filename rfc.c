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
extern int	    *rule_scales[FIELDS];

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
cbm_t		*major_cbms[PHASES][MAXCHUNKS];
cbm_t		*minor_cbms[PHASES][MAXCHUNKS];
int		num_major_cbms[PHASES][MAXCHUNKS];
int		num_minor_cbms[PHASES][MAXCHUNKS];
cbm_fullid_t	*full_cbms[PHASES][MAXCHUNKS];
int		num_full_cbms[PHASES][MAXCHUNKS];

block_table_t	*block_tables[PHASES][MAXCHUNKS];
// phase tables contaiting CBM ids for each chunk at each phase
cbm_fullid_t	*phase_tables[PHASES][MAXCHUNKS];
int		phase_table_sizes[PHASES][MAXCHUNKS];


// cbm_lookup() works slow when there is a large number of CBMs,
// To speed up, we can limit its search to CBMs with the same rulesum
// A hash table hashing on CBM's rulesum is introduced for this purpose
// Alert: no less than 65536, otherwise phase 0 full cbm formulation will go wrong!
#define HASH_TAB_SIZE   99787
int     *cbm_hash[HASH_TAB_SIZE];
int     cbm_hash_size[HASH_TAB_SIZE];   
int     cbm_hash_num[HASH_TAB_SIZE];    

// a hash table for looking up existing full CBM ids (major_id + minor_id)
cbm_fullid_t    *fullid_hash[HASH_TAB_SIZE];
int	    fullid_hash_size[HASH_TAB_SIZE];   
int	    fullid_hash_num[HASH_TAB_SIZE];    

// data structures for examining the two bottleneck functions, cmb_lookup(), cbm_2intersect()
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
void add_cbm_hash(int h, cbm_t *cbm)
{
    cbm_hash[h][cbm_hash_num[h]] = cbm->id;
    if (++cbm_hash_num[h] == cbm_hash_size[h]) {
	cbm_hash_size[h] <<= 1;
	cbm_hash[h] = (int *) realloc(cbm_hash[h], cbm_hash_size[h]*sizeof(int));
    }
}


void init_fullid_hash()
{
    int	i;

    for (i = 0; i < HASH_TAB_SIZE; i++) {
        fullid_hash[i] = (cbm_fullid_t *) malloc(2*sizeof(cbm_fullid_t));
        fullid_hash_size[i] = 2;
        fullid_hash_num[i] = 0;
    }
}


void free_fullid_hash()
{
    int i;

    for (i = 0; i < HASH_TAB_SIZE; i++)
        free(fullid_hash[i]);
}


int fullid_hash_func(int major, int minor)
{
    return ((major << 16) + minor) % HASH_TAB_SIZE;
}


// a new CBM is added into the hash table to prevent duplicate CBMs added into the CBM set in the future
void add_fullid_hash(cbm_fullid_t fullid)
{
    int	    h = fullid_hash_func(fullid.major, fullid.minor);

    fullid_hash[h][fullid_hash_num[h]] = fullid;
    if (++fullid_hash_num[h] == fullid_hash_size[h]) {
	fullid_hash_size[h] <<= 1;
	fullid_hash[h] = (cbm_fullid_t *) realloc(fullid_hash[h], fullid_hash_size[h]*sizeof(cbm_fullid_t));
    }
}


int cbm_fullid_lookup(int major, int minor)
{
    int	    h, i, n, id, match = 0;

    h = fullid_hash_func(major, minor);

    for (i = 0; i < fullid_hash_num[h]; i++) {
	if ((fullid_hash[h][i].major == major) && (fullid_hash[h][i].minor == minor))
	    return i;
    }
    return -1;
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

    if (cbm_set == NULL)
	return -1;

    h = rulesum % HASH_TAB_SIZE;
    for (i = 0; i < cbm_hash_num[h]; i++) {
	id = cbm_hash[h][i];
	if (cbm_set[id].nrules != nrules)
	    continue;
	if (memcmp(rules, cbm_set[id].rules, nrules*sizeof(uint16_t)) == 0)
	    return id;
    }
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
// and add it into the CBM set of current < phase, chunk> 
int new_cbm(int phase, int chunk, int type, uint16_t *rules, uint16_t nrules, int rulesum)
{
    int		*pnums, cbm_id, h;
    cbm_t	**pcbms;

    if (type == MINOR_RULE) {
	pcbms = minor_cbms[phase];
	pnums = num_minor_cbms[phase];
    } else {
	pcbms = major_cbms[phase];
	pnums = num_major_cbms[phase];
    }

    // increase CBM memory at a step of 64k elements
    if ((pnums[chunk] & 0xFFFF) == 0) 
	pcbms[chunk] = realloc(pcbms[chunk], (pnums[chunk]+0x10000) * sizeof(cbm_t));

    cbm_id = pnums[chunk];
    pcbms[chunk][cbm_id].id = cbm_id;
    pcbms[chunk][cbm_id].rulesum = rulesum;
    pcbms[chunk][cbm_id].nrules = nrules;
    pcbms[chunk][cbm_id].rules = (uint16_t *) malloc(nrules*sizeof(uint16_t));
    memcpy(pcbms[chunk][cbm_id].rules, rules, nrules*sizeof(uint16_t));
    pnums[chunk]++;

    h = pcbms[chunk][cbm_id].rulesum % HASH_TAB_SIZE;
    add_cbm_hash(h, &pcbms[chunk][cbm_id]);

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


/*
// for block type statistics on the original phase table scheme
int get_block_type(cbm_fullid_t *table, int b1, int b2, int n1, int n2)
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
*/


int is_minor_rule(uint16_t rule, int field)
{
    return rule_scales[field][rule] == 0 ? 1 : 0;
}


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



//-------------------------------------------------------------------------------------------------
//
// Section phase-0: functions for phase-0 table generation
//
//-------------------------------------------------------------------------------------------------


// given an end point on a chunk, collect rules covering it
int collect_epoint_rules(int chunk, int point, int type, uint16_t *rules, int *rulesum)
{
    int		f1, f2, k, low, high;
    uint16_t	nrules = 0, i;

    f1 = chunk_to_field[chunk];
    f2 = (f1 == 0) ? 1 : 0;
    k = shamt[chunk];
    *rulesum = 0;
    for (i = 0; i < numrules; i++) {
	// only filter out minor/major rules for SIP & DIP chunks accordingly
	if ((f1 < 2) && (type == MAJOR_RULE)) {
	    if (is_minor_rule(i, f1) || is_minor_rule(i, f2))
	    continue;
	}
	if ((f1 < 2) && (type == MINOR_RULE)) {
	    if ( !is_minor_rule(i, f1) && !is_minor_rule(i, f2))
	    continue;
	}
	low = ruleset[i].field[f1].low >> k & 0xFFFF;
	high = ruleset[i].field[f1].high >> k & 0xFFFF;
	if (low <= point && high >= point) {
	    rules[nrules++] = i;
	    *rulesum += i;
	}
    }
    return nrules;
}


void gen_cbms(int chunk, int type)
{
    uint16_t	rules[MAXRULES], nrules; 
    int		rulesum, point, next_point, cbm_id, i, j, table_size = 65536;

    init_cbm_hash();

    if (type == MINOR_RULE)
	// first generate a default empty minor CBM
	new_cbm(0, chunk, MINOR_RULE, NULL, 0, 0);

    for (i = 0; i < num_epoints[chunk]; i++) {
	// 1. generate a cbm
	point = epoints[chunk][i];
	nrules = collect_epoint_rules(chunk, point, type, rules, &rulesum);

	// 2. check whether the generated cbm exists
	if (type == MINOR_RULE)
	    cbm_id = cbm_lookup(rules, nrules, rulesum, minor_cbms[0][chunk]);
	else
	    cbm_id = cbm_lookup(rules, nrules, rulesum, major_cbms[0][chunk]);
	if (cbm_id < 0) // 3. this is a new cbm, add it to the cbm_set 
	    cbm_id = new_cbm(0, chunk, type, rules, nrules, rulesum);

	// 4. fill the corresponding p0 chunk table with the eqid (cbm_id)
	next_point = (i == num_epoints[chunk] - 1) ? 65536 : epoints[chunk][i+1];
	for (j = point; j < next_point; j++) {
	    if (type == MINOR_RULE)
		phase_tables[0][chunk][j].minor = cbm_id;
	    else
		phase_tables[0][chunk][j].major = cbm_id;
	}
    }
    free_cbm_hash();
}


int form_full_cbms(int chunk)
{
    int		f, n, i, j, major, minor;
    cbm_fullid_t	*p;

    init_fullid_hash();

    f = chunk_to_field[chunk];

    if (f >= 2) {	// for other fields: only major cbms
	n = num_major_cbms[0][chunk];
	num_full_cbms[0][chunk] = n;
	full_cbms[0][chunk] = (cbm_fullid_t *) malloc(n*sizeof(cbm_fullid_t));
	p = full_cbms[0][chunk];
	for (i = 0; i < n; i++) {
	    p[i].major = major_cbms[0][chunk][i].id;
	    p[i].minor = 0;
	}
	return n;
    }

    // for SIP & DIP fields: both major & minor cbms
    full_cbms[0][chunk] = (cbm_fullid_t *) malloc((MAXRULES*2+2)*sizeof(cbm_fullid_t));
    p = full_cbms[0][chunk];
    n = 0;
    
    for (i = 0; i < phase_table_sizes[0][chunk]; i++) {
	major = phase_tables[0][chunk][i].major;
	minor = phase_tables[0][chunk][i].minor;
	if (cbm_fullid_lookup(major, minor) < 0) {
	    p[n].major = major;
	    p[n].minor = minor;
	    add_fullid_hash(p[n]);
	    n++;
	}
    }
    full_cbms[0][chunk] = (cbm_fullid_t *) realloc(full_cbms[0][chunk], n*sizeof(cbm_fullid_t));
    num_full_cbms[0][chunk] = n;

    free_fullid_hash();
    return n;
}


// phase 0: generate CBMs for a chunk in phase 0, and populate the corresponding phase table with
// the corresponding CBM ids
void gen_p0_cbms(int chunk)
{
    uint16_t	rules[MAXRULES], nrules; 
    int		rulesum, point, next_point, cbm_id, i, j, f, table_size = 65536;

    f = chunk_to_field[chunk];

    phase_table_sizes[0][chunk] = table_size;
    phase_tables[0][chunk] = (cbm_fullid_t *) calloc(table_size, sizeof(cbm_fullid_t));

    gen_cbms(chunk, MAJOR_RULE);
    if (f < 2) {    // only SIP & DIP fields handle minor rules
	gen_cbms(chunk, MINOR_RULE);
    }
    // global cbms are constructed for each unique <major, minor> pair of cbms
    form_full_cbms(chunk);

    printf("Chunk[%d]: %d CBMs (major:%d, minor:%d)\n", 
	    chunk, num_full_cbms[0][chunk], num_major_cbms[0][chunk], num_minor_cbms[0][chunk]);
}


// phase 0: generate phase tables for phase 0
int gen_p0_tables()
{
    int		chunk;

    for (chunk = 0; chunk < MAXCHUNKS; chunk++) {
	gen_p0_cbms(chunk);
	//do_cbm_stats(0, chunk, 0);
    }
    //dump_intersect_stats();
    bzero(intersect_stats, MAXRULES*2*sizeof(long));
}



//--------------------------------------------------------------------------------------------------
//
// Section crossprod: crossproducting phases
//
//--------------------------------------------------------------------------------------------------


// intersecting the rulelists of two CBMs (each from current CBMs for constructing a CBM set in next phase)
int cbm_intersect(uint16_t *rules, int *rulesum, cbm_t *c1, cbm_t *c2)
{
    int		n = 0, ncmp = 0;
    uint16_t	i = 0, j = 0;

    *rulesum = 0;
    while (i < c1->nrules && j < c2->nrules) {
	if (c1->rules[i] == c2->rules[j]) {
	    rules[n++] = c1->rules[i];
	    *rulesum += c1->rules[i];
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


// for all phases:   major = major1 x major2
// for only phase 1: minor = minor1 x minor2
// for other phases: minor = minor1 x major2 + major1 x minor2 + minor1 x minor 2
int crossprod_block(int phase, int chunk, int ch1, int ch2, int b1, int b2, int n1, int n2)
{
    int		start1, end1, start2, end2, i, j, rulesum, n; 
    int		major_id1, major_id2, minor_id1, minor_id2, major_id, minor_id;
    uint16_t	rules[MAXRULES], nrules;
    cbm_t	*major1, *major2, *minor1, *minor2;

    start1 = b1 * BLOCKSIZE;
    end1 = (b1 + 1) * BLOCKSIZE;
    if (end1 > n1)
	end1 = n1;
    start2 = b2 * BLOCKSIZE;
    end2 = (b2 + 1) * BLOCKSIZE;
    if (end2 > n2)
	end2 = n2;

    major1 = major_cbms[phase-1][ch1];
    minor1 = minor_cbms[phase-1][ch1];
    major2 = major_cbms[phase-1][ch2];
    minor2 = minor_cbms[phase-1][ch2];

    n = num_full_cbms[phase][chunk];

    printf("**b%dxb%d**\n", b1, b2);
    for (i = start1; i < end1; i++) {
	major_id1 = full_cbms[phase-1][ch1][i].major;
	minor_id1 = full_cbms[phase-1][ch1][i].minor;
	for (j = start2; j < end2; j++) {
	    major_id2 = full_cbms[phase-1][ch2][j].major;
	    minor_id2 = full_cbms[phase-1][ch2][j].minor;
	    // major = major1 x major2
	    nrules = cbm_intersect(rules, &rulesum, &major1[major_id1], &major2[major_id2]);
	    major_id = cbm_lookup(rules, nrules, rulesum, major_cbms[phase][chunk]);
	    if (major_id < 0)
		major_id = new_cbm(phase, chunk, MAJOR_RULE, rules, nrules, rulesum);
	    // minor = minor1 x minor2
	    nrules = cbm_intersect(rules, &rulesum, &minor1[minor_id1], &minor2[minor_id2]);
	    minor_id = cbm_lookup(rules, nrules, rulesum, minor_cbms[phase][chunk]);
	    if (minor_id < 0)
		minor_id = new_cbm(phase, chunk, MINOR_RULE, rules, nrules, rulesum);
	    
	    // if this <major, minor> pair is new, add it to cbm_full set
	    if (cbm_fullid_lookup(major_id, minor_id) < 0) {
		if ((n & 0xFFFF) == 0) 
		    full_cbms[phase][chunk] = realloc(full_cbms[phase][chunk], (n + 0x10000) * sizeof(cbm_fullid_t));
		full_cbms[phase][chunk][n].major = major_id;
		full_cbms[phase][chunk][n].minor = minor_id;
		add_fullid_hash(full_cbms[phase][chunk][n]);
		n++;
	    }
	    printf("%d/%d, ", major_id, minor_id);
	}
	printf("\n");
    }
    num_full_cbms[phase][chunk] = n;
}


// for chunks with both major & minor rule sets (SIP & DIP chunks)
int crossprod_full(int phase, int chunk)
{
    int	    ch1, ch2, n1, n2, nb1, nb2, i, j;

    init_cbm_hash();
    init_fullid_hash();

    switch (phase) {
    case 1:
	if (chunk == 0) {
	    ch1 = 1;
	    ch2 = 0;
	} else {
	    ch1 = 3;
	    ch2 = 2;
	}
	break;
    case 2:
	ch1 = 0;
	ch2 = 1;
	break;
    default:	    // phase 3 => the final phase
	ch1 = 0;
	ch2 = 1;
	break;
    }

    n1 = num_full_cbms[phase-1][ch1];
    n2 = num_full_cbms[phase-1][ch2];
    nb1 = n1 / BLOCKSIZE;
    if (n1 % BLOCKSIZE != 0) nb1++;
    nb2 = n2 / BLOCKSIZE;
    if (n2 % BLOCKSIZE != 0) nb2++;

    for (i = 0; i < nb1; i++) {
	for (j = 0; j < nb2; j++) {
	    crossprod_block(phase, chunk, ch1, ch2, i, j, n1, n2);
	}
    }

    free_fullid_hash();
    free_cbm_hash();

    printf("Chunk[%d]: %d CBMs (major:%d, minor:%d)\n", 
	    chunk, num_full_cbms[phase][chunk], num_major_cbms[phase][chunk], num_minor_cbms[phase][chunk]);
}


// do phase 1 crossproducting for three pairs of chunks in phase 0,
// Alert 1: the protocol chunk is left for crossproducting in next phase
// Alert 2: be careful of the order of crosspoducting for each pair of chunks (as commented in below code)
int p1_crossprod()
{
    // SIP[31:16] x SIP[15:0]
    crossprod_full(1, 0);
    
    // DIP[31:16] x DIP[15:0]
    crossprod_full(1, 1);

    // DP x SP
    //crossprod_major(1, 2);
}


int p2_crossprod()
{
    // SIP x DIP
    crossprod_full(2, 0);
}

/*
int p1_crossprod()
{
    int	    table_size, n1, n2;
    cbm_t   *cbms1, *cbms2;
    int	    rest_fields[FIELDS] = {0, 1, 1, 1, 1};

    // SIP[31:16] x SIP[15:0]
    n1 = phase_num_cbms[0][1];
    n2 = phase_num_cbms[0][0];
    table_size = n1 * n2;
    cbms1 = phase_cbms[0][1];
    cbms2 = phase_cbms[0][0];
    phase_table_sizes[1][0] = table_size;
    phase_tables[1][0] = (int *) malloc(table_size*sizeof(int));
    crossprod_2chunk(1, 0, cbms1, n1, cbms2, n2, rest_fields);
    printf("Chunk[%d]: %d CBMs in Table[%d]\n", 0, phase_num_cbms[1][0], table_size);
    //do_cbm_stats(1, 0, 0);
    //dump_phase_table(phase_tables[1][0], n1, n2);

    // DIP[31:16] x DIP[15:0]
    rest_fields[0] = 1;
    rest_fields[1] = 0;
    n1 = phase_num_cbms[0][3];
    n2 = phase_num_cbms[0][2];
    table_size = n1 * n2;
    cbms1 = phase_cbms[0][3];
    cbms2 = phase_cbms[0][2];
    phase_table_sizes[1][1] = table_size;
    phase_tables[1][1] = (int *) malloc(table_size*sizeof(int));
    crossprod_2chunk(1, 1, cbms1, n1, cbms2, n2, rest_fields);
    printf("Chunk[%d]: %d CBMs in Table[%d]\n", 1, phase_num_cbms[1][1], table_size);
    //do_cbm_stats(1, 1, 0);
    //dump_phase_table(phase_tables[1][1], n1, n2);

    // DP x SP
    rest_fields[1] = 1;
    rest_fields[3] = rest_fields[4] = 0;
    n1 = phase_num_cbms[0][6];
    n2 = phase_num_cbms[0][5];
    table_size = n1 * n2;
    cbms1 = phase_cbms[0][6];
    cbms2 = phase_cbms[0][5];
    phase_table_sizes[1][2] = table_size;
    phase_tables[1][2] = (int *) malloc(table_size*sizeof(int));
    crossprod_2chunk(1, 2, cbms1, n1, cbms2, n2, rest_fields);
    printf("Chunk[%d]: %d CBMs in Table[%d]\n", 2,phase_num_cbms[1][2], table_size);
    do_cbm_stats(1, 2, 0);
    //dump_phase_table(phase_tables[1][2], n1, n2);

    //dump_intersect_stats();
    bzero(intersect_stats, MAXRULES*2*sizeof(long));
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
    printf("***Phase 0 spent %lds\n\n", (clock()-t)/1000000);

    t = clock();
    p1_crossprod();
    printf("***Phase 1 spent %lds\n\n", (clock()-t)/1000000);

    t = clock();
    p2_crossprod();
    printf("***Phase 2 spent %lds\n\n", (clock()-t)/1000000);

    /*
    t = clock();
    p3_crossprod();
    printf("***Phase 3 spent %lds\n\n", (clock()-t)/1000000);

    do_rfc_stats();
    //dump_hash_stats();
    */

    printf("\n");
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

// XXX: for blocking test purpose, should be removed otherwise
calc_rule_scales();
    // constructing RFC tables
    construct_rfc();
}  
