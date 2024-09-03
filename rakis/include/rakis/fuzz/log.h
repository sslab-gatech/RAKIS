#include <stdio.h>

#define log_error(args...) printf(args); printf("\n");fflush(stdout);
#define log_debug(args...) printf(args); printf("\n"); fflush(stdout);
#define log_always(args...) printf(args); printf("\n"); fflush(stdout);
