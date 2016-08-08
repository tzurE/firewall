#ifndef _DATA_LEAK_H_
#define _DATA_LEAK_H_


#include "fw.h"
#include "hookfuncs.h"
#include "stateless_funcs.h"
#include "stateful_funcs.h"
#include "log.h"

int search_for_data_leak(char* data);


#endif // _DATA_LEAK_H_