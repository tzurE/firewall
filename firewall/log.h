#ifndef _LOG_H_
#define _LOG_H_

#include "fw.h"
#include "stateless_funcs.h"
#include "hookfuncs.h"

typedef struct {
	log_row_t log_entry;
	struct log_node *next;
} log_node;

extern int log_size_var;
extern log_node *log_list;

int clear_main_log(void);
int insert_log(rule_t *packet, rule_t *rule, reason_t reason, int action, int hooknum);

#endif