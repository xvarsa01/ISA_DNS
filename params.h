#ifndef PARAMS_H
#define PARAMS_H

#include <stdbool.h>

typedef struct {
    bool verbose;
    char *pcapfile;
    char *domainsfile;
    char *translationsfile;
} global_params;

extern global_params params;

#endif