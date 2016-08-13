#ifndef _DATA_LEAK_H_
#define _DATA_LEAK_H_


#include "fw.h"
#include "hookfuncs.h"
#include "stateless_funcs.h"
#include "stateful_funcs.h"
#include "log.h"

// for isspace
#include <linux/ctype.h>

// every msg carries some round brackets, so the  overall has a bit more brackets
#define BRACKETS_THEESHOLD (12)
// sqaure should be a little
#define SRACKETS_THEESHOLD (3)
// curly should be minimal
#define CBRACKETS_THEESHOLD (3)



int search_for_data_leak(char* data);


#endif // _DATA_LEAK_H_