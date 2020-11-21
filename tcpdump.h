#ifndef __TCPDUMP_H__
#define __TCPDUMP_H__

#include "error.h"

void sigint_handler(int sig);

error_status_t my_tcpdump(const char* if_name);


#endif //__TCPDUMP_H__
