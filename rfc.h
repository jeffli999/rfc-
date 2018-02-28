#include <stdint.h>

#define MAXRULES	65536
#define FIELDS		5
#define MAXCHUNKS	7
#define PHASES		4

struct range{
    unsigned low;
    unsigned high;
};

typedef struct pc_rule {
    struct range field[FIELDS];
} pc_rule_t;

typedef struct cbm_entry {
    int		id;
    int		rulesum;
    uint16_t	nrules;
    uint16_t	*rules;
} cbm_t;

typedef struct cbm_stat {
    int	id;
    int	count;
} cbm_stat_t;
