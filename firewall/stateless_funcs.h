#include "fw.h"
#include "hookfuncs.h"

extern rule_t rules[50];

int check_rule_exists(rule_t packet, int hooknum);