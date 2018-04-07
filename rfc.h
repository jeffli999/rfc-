#include <stdint.h>

#define MAXRULES	65536
#define FIELDS		5
#define MAXCHUNKS	7
#define PHASES		4

#define BLOCKSIZE	16	// ALERT: BLOCKSIZE <= 16 (4, 8, or 16)

typedef struct range {
    unsigned low;
    unsigned high;
} range_t;


typedef struct pc_rule {
    range_t field[FIELDS];
} pc_rule_t;


//enum LOCAL_TYPE {NOT_LOCAL, ROW_LOCAL, COL_LOCAL, POINT_LOCAL};
enum BLOCK_TYPE {ROW_BLOCK, COL_BLOCK, MATRIX16_BLOCK, MATRIX32_BLOCK, MATRIX48_BLOCK, MATRIX_BLOCK};

typedef struct cbm_entry {
    int		id;
    int		rulesum;
    uint32_t	order;	    // shuffle order in the CBM set
    int		run;	    // #runs produced from crossproducting with another CBM set
    uint16_t	nrules;
    uint16_t	*rules;
} cbm_t;


typedef struct cbm_stat {
    int	id;
    int gminor, lminor;
    int	count;
} cbm_stat_t;


typedef struct {
    int		id;
    uint32_t	count;
} id_count_t;


typedef struct {
    uint8_t loc : 4;	// dirt location in a line (row or column)
    uint8_t id  : 4;	// dirt id in a block (only allow 15 dirts, 1111 means no dirt in this line)
} dirt_code_t;


typedef struct {
    uint32_t	type : 3;   // block type
    uint32_t	id :  29;   // index of this block in the table of this type
} block_entry_t;


#define ARRAY_BLOCK_SIZE    (BLOCKSIZE*8 + (BLOCKSIZE*BLOCKSIZE >> 3))
typedef struct {
    uint8_t	map[BLOCKSIZE*BLOCKSIZE >> 3];
    int		cbms[BLOCKSIZE << 1];
    int		row_size, col_size;
} array_block_t;


/*
typedef struct {
    int		prime_cbms[BLOCKSIZE];
    int		*dirts;	    // actual dirt CBMs (at most 15 different CBMs allowed)
    int		num_dirts;  // only needed for statsitis purposes, can be removed in production system
    dirt_code_t	dirt_code[BLOCKSIZE];	// to get the dirt locations and dirt id in the block dirts
} array_block_t;
*/


#define MATRIX16_BLOCK_SIZE    (64 + (BLOCKSIZE*BLOCKSIZE >> 1))
typedef struct {
    uint8_t	map[BLOCKSIZE*BLOCKSIZE >> 1];
    int		cbms[16];
    int		row_size, col_size;
} matrix16_block_t;


#define MATRIX32_BLOCK_SIZE    (128 + (BLOCKSIZE*BLOCKSIZE))
typedef struct {
    uint8_t	map[BLOCKSIZE*BLOCKSIZE];
    int		cbms[32];
    int		row_size, col_size;
} matrix32_block_t;


#define MATRIX48_BLOCK_SIZE    (192 + (BLOCKSIZE*BLOCKSIZE))
typedef struct {
    uint8_t	map[BLOCKSIZE*BLOCKSIZE];
    int		cbms[48];
    int		row_size, col_size;
} matrix48_block_t;


#define MATRIX_BLOCK_SIZE    (BLOCKSIZE*BLOCKSIZE*4)
typedef struct {
    int		cbms[BLOCKSIZE][BLOCKSIZE];
    int		row_size, col_size;
} matrix_block_t;


typedef struct {
    int	top, bottom, left, right;
    int	size;
    int pop_cbm;    // the most populous CBM in this partition
    int	row_bound, col_bound;	// row & col bounds of the sub-partition w.r.t partitioning on pop_cbm
} partition_t;
