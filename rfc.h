#include <stdint.h>

#define MAXRULES	65536
#define FIELDS		5
#define MAXCHUNKS	7
#define PHASES		4

#define BLOCKSIZE	8	// ALERT: BLOCKSIZE <= 16 (4, 8, or 16)
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


enum LOCAL_TYPE {NOT_LOCAL, ROW_LOCAL, COL_LOCAL, POINT_LOCAL};

typedef struct cbm_entry {
    int		id;
    int		rulesum;
    uint16_t	nrules;
    uint16_t	*rules;
} cbm_t;


typedef struct cbm_stat {
    int	id;
    int gminor, lminor;
    int	count;
} cbm_stat_t;


/*
 A data structure for blocking RFC
 1. block types:
 - POINT: all CBMs are the same in the block
 - ROW: all rows of CBMS are the same
 - COL: all columns of CBMs are the same
 - MATRIX: other situations
 =================================================================================================
 2. MATRIX transform: a matrix block may be transformed to other blocks types for space compaction
    if it contains only a few certain "dirt" CBMs
    1) Condition for transforming: a MATRIX block with at most 2 LINE dirts and 1 POINT dirt
    2) Encoding of dirts: 2-bit dirt for each row/col
       00: not a dirt
       01: a POINT dirt
       10: the first LINE dirt (can be either ROW or COL)
       11: the second LINE dirt (can be either ROW or COL)
    3) Meaning of a point [r, c] in a block with the dirt encodings
       [00, 00]: a non-dirt point
       [00, 01]: a non-dirt point
       [00, 10]: a point on a dirt column, which is the first LINE dirt
       [00, 11]: a point on a dirt column, which is the second LINE dirt
       --------------------------------------------------------------------------------------------
       [01, 00]: a non-dirt point
       [01, 01]: a dirt point, which is the first dirty point
       [01: 10]: a point on a dirt column, which is the first LINE dirt
                 NOTE: if this point is different to the corresponding points on other columns of
      	   the same dirt LINE, this block should be treated as a MATRIX block
       [01: 11]: a point on a dirt column, which is the second LINE dirt
                 NOTE: if this point is different to the corresponding points on other columns of
		   the same dirt LINE, this block should be treated as a MATRIX block
       ---------------------------------------------------------------------------------------------
       [10: 00]: a point on a dirt row, which is the first LINE dirt
       [10, 01]: a point on a dirt row, which is the first LINE dirt
                 NOTE: if this point is different to the corresponding points on other rows of the
		   same dirt LINE, this block should be treated as a MATRIX block
       [10, 10]: an INVALID combination, as 10 indicates the first LINE dirt, which cannot be
                 both a row and a column at the same time
       [10, 11]: a dirt point crossed by a dirt row (the first LINE dirt) and a dirt column (the
	           second LINE dirt), and this dirt point is the second dirt point (irrespective of
	           whether the first dirty point [01, 01] exists or not, it is always stored as the
      	   second dirt point for convenience of simple addressing and fast access)
       ---------------------------------------------------------------------------------------------
       [11, 00]: a point on a dirt row, which is the second LINE dirt
       [11, 01]: a point on a dirt row, which is the second LINE dirt
                 NOTE: if this point is different to the corrsponding points on other rows of the
		   same dirt LINE, this block should be treated as a MATRIX block
       [11, 10]: a dirt point crossed by a dirt row (the second LINE dirt) and a dirt column (the
      	   first LINE dirt), and this dirt point is the third dirt point (irrespective of
	           whether the first dirt point [01, 01] exists or not, it is always stored as the
		 third dirt point for convenience of simple addressing and fast access)
       [11, 11]: an INVALID combination, as 11 indicates the second LINE dirt, which cannot be 
                 both a row and a column at the same time
       =============================================================================================
       In summary: at most 2 LINE dirts (2-row, 2-col, or 1-row + 1-col) and 3 POINT dirts
       ([01, 01], [10, 11], [11, 10]) are allowed. 
       Note: rows or columns with the same values can share the same dirt LINE code; Similarly,
       points having the same value can share the same dirt POINT code as well
    4) Examples:
       a) MATRIX block => POINT block with two LINE dirts and a POINT dirt: 
          - COL dirt [*, 6] = [1 1 4 1 6 7 8 9]
	  - ROW dirt [2, *] = [2 2 3 3 3 3 4 3]
          - POINT dirt [4, 2] = 5

          | 00 00 01 00 00 00 10 00
       ---+-------------------------
       00 | 0  0  0  0  0  0  1  0
       00 | 0  0  0  0  0  0  1  0
       11 | 2  2  3  3  3  3  4  3
       00 | 0  0  0  0  0  0  1  0
       01 | 0  0  5  0  0  0  6  0
       00 | 0  0  0  0  0  0  7  0
       00 | 0  0  0  0  0  0  8  0
       00 | 0  0  0  0  0  0  9  0
       
       b) MATRIX block => ROW block with a LINE dirt and a POINT dirt:

          | 00 00 01 00 00 00 10 00
       ---+-------------------------
       00 | 0  1  2  4  3  0  0  4
       00 | 0  1  2  0  3  0  0  4
       11 | 2  2  3  3  3  3  4  3
       00 | 0  0  0  0  0  0  1  0
       01 | 0  0  5  0  0  0  6  0
       00 | 0  0  0  0  0  0  7  0
       00 | 0  0  0  0  0  0  8  0
       00 | 0  0  0  0  0  0  9  0
         
*/
typedef struct block_table {
    uint8_t	type;	    // block type
    uint32_t	row_dirts;  // 
    uint32_t	col_dirts;  
} block_table_t;
