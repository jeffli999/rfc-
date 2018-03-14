#ifndef RFC_H
#define RFC_H

#include <stdint.h>

#define MAXRULES	65536
#define FIELDS		5
#define MAXCHUNKS	7
#define PHASES		4

#define BLOCKSIZE	16

enum BLOCK_TYPE {MATRIX_BLOCK, ROW_BLOCK, COL_BLOCK, POINT_BLOCK};
enum RULE_TYPE {ALL_RULE, MAJOR_RULE, MINOR_RULE};

typedef struct range {
    unsigned low;
    unsigned high;
} range_t;

typedef struct pc_rule {
    range_t field[FIELDS];
} pc_rule_t;

typedef struct cbm_entry {
    int		id;
    int		rulesum;
    uint16_t	nrules;
    uint16_t	*rules;
} cbm_t;


typedef struct cbm_id {
    int		major;	    // cbm with only major rules in this chunk
    int		minor;	    // cbm with only minor rules in this chunk
} cbm_id_t;

typedef struct cbm_stat {
    int	id;
    int gminor, lminor;
    int	count;
} cbm_stat_t;


typedef struct block_table {
    uint8_t	type;	    // block type
    uint8_t	gminor;	    // at most 2 resulting CBMs set by global minor rules is allowed
    uint16_t	lminor;	    // at most 2 resulting CBMs by local minor rules is supported
    int		base;	    // start address in the phase table
} block_table_t;

#endif
