#include <stdint.h>

#define MAXRULES	65536
#define FIELDS		5
#define MAXCHUNKS	7
#define PHASES		4

#define BLOCKSIZE	8	// ALERT: BLOCKSIZE <= 16 (4, 8, or 16)

typedef struct range {
    unsigned low;
    unsigned high;
} range_t;


typedef struct pc_rule {
    range_t field[FIELDS];
} pc_rule_t;


//enum LOCAL_TYPE {NOT_LOCAL, ROW_LOCAL, COL_LOCAL, POINT_LOCAL};
enum BLOCK_TYPE {POINT_BLOCK, ROW_BLOCK, COL_BLOCK, MATRIX_BLOCK};

typedef struct cbm_entry {
    int		id;
    int		rulesum;
    int		ndirts;	    // total block dirts involved in crossproducted matrix blocks
    uint16_t	nrules;
    uint16_t	*rules;
} cbm_t;


typedef struct cbm_stat {
    int	id;
    int gminor, lminor;
    int	count;
} cbm_stat_t;


typedef struct {
    uint8_t loc : 4;	// dirt location in a line (row or column)
    uint8_t id  : 4;	// dirt id in a block (only allow 15 dirts, 1111 means no dirt in this line)
} dirt_code_t;


typedef struct {
    uint32_t	type : 2;   // block type
    uint32_t	id :  30;   // index of this block in the table of this type
} block_entry_t;


typedef struct {
    int		prime_cbm;  // a point block has a unique prime CBM in this block
    int		*dirts;	    // actual dirt CBMs (at most 15 different CBMs allowed)
    int		num_dirts;  // only needed for statsitis purposes, can be removed in production system
    dirt_code_t	dirt_code[BLOCKSIZE];	// to get the dirt locations and dirt id in the block dirts
} point_block_t;


typedef struct {
    int		prime_cbms[BLOCKSIZE];
    int		*dirts;	    // actual dirt CBMs (at most 15 different CBMs allowed)
    int		num_dirts;  // only needed for statsitis purposes, can be removed in production system
    dirt_code_t	dirt_code[BLOCKSIZE];	// to get the dirt locations and dirt id in the block dirts
} array_block_t;


typedef struct {
    int		cbms[BLOCKSIZE][BLOCKSIZE];
    int		row_block, col_block;
    int		row_size, col_size;
} matrix_block_t;
