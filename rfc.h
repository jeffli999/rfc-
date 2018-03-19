#include <stdint.h>

#define MAXRULES	65536
#define FIELDS		5
#define MAXCHUNKS	7
#define PHASES		4

#define BLOCKSIZE	16
#define MATRIX_BLOCK	0
#define ROW_BLOCK	1
#define COL_BLOCK	2
#define POINT_BLOCK	3

typedef struct range {
    unsigned low;
    unsigned high;
} range_t;


typedef struct pc_rule {
    range_t field[FIELDS];
} pc_rule_t;


enum LOCAL_TYPE {NO_LOCAL, ROW_LOCAL, COL_LOCAL, POINT_LOCAL};

typedef struct cbm_entry {
    int		id;
    // whether it contains local rules (a rule is local if it cannot appear in other CBMs in a chunk)
    // 4 types by considering rule locals in its two crossproducting CBMs (CBM1 x CBM2): 
    // NO_LOCAL (0b00):  not belong to the following 3 cases
    // COL_LOCAL (0b01): no local rules in its own, but with local rules in CBM2
    // ROW_LOCAL (0b10): no local rules in its own, but with local rules in CBM1
    // POINT_LOCAL (0b11): with local rules in its own
    int		local;	    
    int		rulesum;
    uint16_t	nrules;
    uint16_t	*rules;
} cbm_t;


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
