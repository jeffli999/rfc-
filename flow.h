#define	    MAXFLOWS	20000000
#define	    INITFLOWS	 1000000

typedef struct flow_entry {
    unsigned int    sip, dip;
    uint8_t	    proto;
    uint16_t	    sp, dp;
    uint16_t	    match_rule;
} flow_entry_t;

void create_flows();
void write_flow_trace(FILE *ftrace);
void read_flow_trace(FILE *ftrace);
void dump_one_flow(int i);
void dump_flows();
