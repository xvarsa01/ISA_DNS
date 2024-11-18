#ifndef GENERAL_UTILS_H
#define GENERAL_UTILS_H

#include "params.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>
#include <string.h>
#include <unistd.h>

#include <pcap.h>

void print_interfaces();
void process_args(int argc, char *argv[], char **interface, char **pcapfile, char **domainsfile, char** translationsfile, bool *verbose);
void remove_duplicate_last_line(FILE *fp);
void remove_last_line(FILE *fp);
void print_timestamp();

#endif