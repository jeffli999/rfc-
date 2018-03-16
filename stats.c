#include <stdio.h>
#include "stats.h"
#include "rfc.h"

extern int	epoints[MAXCHUNKS][MAXRULES*2+2];
extern int	num_epoints[MAXCHUNKS];
extern int	num_full_cbms[PHASES][MAXCHUNKS];
extern int	phase_table_sizes[PHASES][MAXCHUNKS];
extern long	intersect_stats[MAXRULES*2];
extern long	hash_stats[10000];

int dump_endpoints()
{
    int	    chunk, i;

    for (chunk = 0; chunk < MAXCHUNKS; chunk++) {
	printf("end_points[%d]: %d\n", chunk, num_epoints[chunk]);
	//
	//for (i = 0; i < num_epoints[chunk]; i++)
	//   printf("%d: %d  ", i, epoints[chunk][i]);
    }
    printf("\n");

}


// statistics on the total number of rule comparisons in cbm_2intersect(), which is the primary bottleneck
void dump_intersect_stats()
{
    int	    i;
    long    total = 0;

    for (i = 0; i < MAXRULES*2; i++) {
	if (intersect_stats[i] > 0) {
	    printf("intersect[%5d]: %7ld / %9ld\n", i, intersect_stats[i], intersect_stats[i]*i);
	    total += intersect_stats[i]*i;
	}
    }
    printf("Total intersect comparisons: %ld\n", total);
}


/*
void dump_hash_stats()
{
    int	    i;
    long    total = 0;

    printf("Statistics on cbm hash lookups\n================================\n");
    for (i = 0; i < 10000; i++) {
	if (hash_stats[i] > 0) {
	    total += hash_stats[i] * i;
	    printf("cbm_lookup[%4d]: %7ld / %8ld\n", i, hash_stats[i], hash_stats[i]*i);
	}
    }
    printf("Total cbm hash lookups: %ld\n", total);
}
*/


void dump_phase_table(int *table, int n1, int n2)
{
    int	    i, j, tid, cbm_id1, cbm_id2, run_len, max_run;

    tid = 0;
    for (i = 0; i < n1; i++) {
	printf("cbm0[%d]\n", i);
	cbm_id1 = table[tid++];
	run_len = 1;
	for (j = 1; j < n2; j++) {
	    cbm_id2 = table[tid++];
	    if (cbm_id2 == cbm_id1) {
		run_len++;
	    } else {
		printf("  %d#%d\n", cbm_id1, run_len);
		cbm_id1 = cbm_id2;
		run_len = 1;
	    }
	}
	printf("  %d#%d\n", cbm_id1, run_len);
    }
}


// print the phase table with run length of eqid in the table >= thresh_rl
void phase_table_stats(int *table, int len, int thresh_rlen)
{
    int	    i, eqid, eqid1, run_len;

    eqid = table[0];
    run_len = 0;
    for (i = 0; i < len; i++) {
	eqid1 = table[i];
	if (eqid1 == eqid) {
	    run_len++;
	} else {
	    if (run_len >= thresh_rlen)
		printf("table[%d]: %d#%d\n", i, eqid, run_len);
	    eqid = eqid1;
	    run_len = 1;
	}
    }
    if (run_len >= thresh_rlen)
	printf("table[%d]: %d#%d\n", len, eqid, run_len);
}


// statistics on the number of minor rules for each CBM in field SIP or DIP in phase 1
/*
int cbm_minor_stats(int field)
{
    cbm_t	*cbms = phase_cbms[1][field];
    cbm_stat_t	*stats;
    int		ncbms, cross_field, i, r;
    uint16_t	rule;

    // if field is SIP, then cross_field DIP, and vice versa
    cross_field = (field == 0) ? 1 : 0;	    
    ncbms = phase_num_cbms[1][field];
    stats = (cbm_stat_t *) calloc(ncbms, sizeof(cbm_stat_t));

    printf("Field[%d] CBM minor rules:\n", field);
    for (i = 0; i < ncbms; i++) {
	stats[i].id = i;
	for (r = 0; r < cbms[i].nrules; r++) {
	    rule = cbms[i].rules[r];
	    if (is_minor_rule(rule, field)) {
		if (is_minor_rule(rule, cross_field))
		    stats[i].lminor++;
		else {
		    stats[i].gminor++;
		    printf("cbm[%d].gminor: %d\n", i, rule);
		}
	    }
	}
	printf("    CBM[%d] %d rules: %d gminor, %d lminor\n", i, cbms[i].nrules, stats[i].gminor, stats[i].lminor);
    }
}
*/


static int cbm_stat_cmp(const void *p, const void *q)
{
    return ((cbm_stat_t *)q)->count - ((cbm_stat_t *)p)->count;
}


// get the 10 most frequent CBMs in a phase table, and output them with their numbers of times in the phase table
// flag = 1: output the detail of each cbm; flag = 0: no detail on each cbm
/*
int do_cbm_stats(int phase, int chunk, int flag)
{
    cbm_stat_t	*stats;
    int		i, k, m, n, total = 0;

    n = phase_num_cbms[phase][chunk];
    stats = (cbm_stat_t *) malloc(n*sizeof(cbm_stat_t));

    for (i = 0; i < phase_num_cbms[phase][chunk]; i++) {
	stats[i].id = i;
	stats[i].count = 0;
    }
    for (i = 0; i < phase_table_sizes[phase][chunk]; i++)
	stats[phase_tables[phase][chunk][i]].count++;
    qsort(stats, phase_num_cbms[phase][chunk], sizeof(cbm_stat_t), cbm_stat_cmp);

    // only look at CBMs contributing at least 1% of the phase table
    m = phase_table_sizes[phase][chunk] / 256;
    m = m < 8 ? 8 : m;
    for (i = 0; i < phase_num_cbms[phase][chunk]; i++) {
	if (stats[i].count <= m)
	    break;
	printf("    CBM[%d] * %d\n", stats[i].id, stats[i].count);
	total += stats[i].count;
	if (flag) {
	    printf("    ");
	    for (k = 0; k < phase_cbms[phase][chunk][stats[i].id].nrules; k++) {
		printf("%u  ", phase_cbms[phase][chunk][stats[i].id].rules[k]);
	    }
	    printf("\n");
	}
    }

    printf("    = %d%%\n", total*100 / phase_table_sizes[phase][chunk]);
    free(stats);
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


// statistics on the sizes of CBM sets and phase tables
int do_rfc_stats()
{
    int	    i, phase_total[4] = {0, 0, 0, 0}, total = 0;

    printf("\nPhase 0:\n");
    printf("====================\n");
    for (i = 0; i < 7; i++) {
	printf("#cbm/#phase-table %d: %d/%d\n", i, num_full_cbms[0][i], 65536);
	phase_total[0] += 65536;
    }
    printf("Total phase-table size: %d\n", phase_total[0]);

    printf("\nPhase 1:\n");
    printf("====================\n");
    for (i = 0; i < 3; i++) {
	printf("#cbm/#phase-table %d: %d/%d\n", i, num_full_cbms[1][i], phase_table_sizes[1][i]);
	phase_total[1] += phase_table_sizes[1][i];
    }
    printf("Total phase-table size: %d\n", phase_total[1]);

    printf("\nPhase 2:\n");
    printf("====================\n");
    for (i = 0; i < 2; i++) {
	printf("#cbm/#phase-table %d: %d/%d\n", i, num_full_cbms[2][i], phase_table_sizes[2][i]);
	phase_total[2] += phase_table_sizes[2][i];
    }
    printf("Total phase-table size: %d\n", phase_total[2]);

    printf("\nPhase 3:\n");
    printf("====================\n");
    printf("#cbm/#phase-table %d: %d/%d\n", i, num_full_cbms[3][0], phase_table_sizes[3][0]);
    phase_total[3] = phase_table_sizes[3][0];

    for (i = 0; i < 4; i++)
	total += phase_total[i];
    printf("\nTotal table size: %d\n", total);
}
