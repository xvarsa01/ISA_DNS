#include "general_utils.h"

// super hack to check if optional arg is present, reference: https://cfengine.com/blog/2021/optional-arguments-with-getopt-long/
#define OPTIONAL_ARGUMENT_IS_PRESENT \
    ((optarg == NULL && optind < argc && argv[optind][0] != '-') \
     ? (bool) (optarg = argv[optind++]) \
     : (optarg != NULL))


/*
    Function prints a list of available network interfaces with their names, descriptions, and flags.
*/
void print_interfaces() {
    pcap_if_t *interfaces;  // Pointer to the list of network interfaces
    char errbuf[PCAP_ERRBUF_SIZE];  // Error buffer

    // Find all available network interfaces
    if (pcap_findalldevs(&interfaces, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return;
    }

    // Print table header
    printf("%-25s %-50s %-10s\n", "interface", "description", "flags");

    // Iterate through the list of interfaces and print them
    pcap_if_t *iface;
    for (iface = interfaces; iface != NULL; iface = iface->next) {
        printf("%-25s %-50s %-10d\n", iface->name, (iface->description ? iface->description : "N/A"), iface->flags);
    }

    pcap_freealldevs(interfaces);
}

/*
    Function processes command-line arguments to set the values of interface, pcapfile, domainsfile, 
    translationsfile, and verbose flag based on user input.
*/
void process_args(int argc, char *argv[], char **interface, char **pcapfile, char **domainsfile, char** translationsfile, bool *verbose) {
    int opt;
    while ((opt = getopt(argc, argv, "vi::p:d:t:")) != -1) {
        switch (opt) {
        case 'v':
            *verbose = true;
            break;
        case 'i':
            if (OPTIONAL_ARGUMENT_IS_PRESENT){
                *interface = optarg;
                break;
            }
            fprintf(stderr, "Interface not specified.\n");
            print_interfaces();
            exit(1);
            
        case 'p':
            if (OPTIONAL_ARGUMENT_IS_PRESENT){
                *pcapfile = optarg;
                break;
            }
            fprintf(stderr, "Pcapfile not specified.\n");
            exit(1);

        case 'd':
            if (OPTIONAL_ARGUMENT_IS_PRESENT){
                *domainsfile = optarg;
                break;
            }
            fprintf(stderr, "Domainsfile not specified.\n");
            exit(1);

            break;
        case 't':
            if (OPTIONAL_ARGUMENT_IS_PRESENT){
                *translationsfile = optarg;
                break;
            }
            fprintf(stderr, "Translationsfile not specified.\n");
            exit(1);

        default:
            fprintf(stderr, "Unexpected option %c\n", opt);
            exit (1);
        }
    }

    if (*interface == NULL && *pcapfile == NULL){
        fprintf(stderr, "Interface or pcapfile must be specified\n");
        exit(1);
    }

    if (*interface != NULL && *pcapfile != NULL){
        fprintf(stderr, "Can not use Interface AND pcapfile together\n");
        exit(1);
    }
}

/*
    Function removes the last line from the given file if that line is already present earlier in the file.
*/
void remove_duplicate_last_line(FILE *fp) {
    char last_line[1024] = {0};
    char current_line[1024] = {0};
    long last_line_position = 0;
    long position_before_read = 0;

    // Move to the beginning of the file for reading
    fseek(fp, 0, SEEK_SET);

    // Find the position and content of the last line
    while (fgets(current_line, sizeof(current_line), fp) != NULL) {
        position_before_read = last_line_position;  // Position before reading new line
        last_line_position = ftell(fp);  // Position after reading
        strncpy(last_line, current_line, sizeof(last_line) - 1);
        last_line[sizeof(last_line) - 1] = '\0'; // Ensure null termination
    }

    // Check for duplicates by rewinding and comparing lines
    rewind(fp);
    bool is_duplicate = false;
    while (ftell(fp) < position_before_read && fgets(current_line, sizeof(current_line), fp) != NULL) {
        if (strcmp(current_line, last_line) == 0) {
            is_duplicate = 1;
            break;
        }
    }

    if (is_duplicate) {
        if (ftruncate(fileno(fp), position_before_read) != 0) {
            fprintf(stderr, "Error removing duplicate line from file\n");
        }
    }
}

/*
     Function removes the last line from a given file.
*/
void remove_last_line(FILE *fp) {
    char current_line[1024] = {0};
    long last_line_position = 0;
    long position_before_last_line = 0;

    // Move to the beginning of the file for reading
    fseek(fp, 0, SEEK_SET);

    // Find the position of the last line
    while (fgets(current_line, sizeof(current_line), fp) != NULL) {
        position_before_last_line = last_line_position;  // Store position before reading new line
        last_line_position = ftell(fp);  // Store the current position after reading the line
    }

    // If the file isn't empty, truncate it to remove the last line
    if (last_line_position > 0) {
        if (ftruncate(fileno(fp), position_before_last_line) != 0) {
            fprintf(stderr, "Error removing last line from file\n");
        }
    }
}

/*
    Function prints the current timestamp in the format "YYYY-MM-DD HH:MM:SS".
*/
void print_timestamp(){
    time_t now;
    time(&now);
    
    // Convert to local time format
    struct tm *local = localtime(&now);
    
    // Create a buffer to hold the formatted time
    char timestamp[20];
    
    // Format the time as YYYY-MM-DD HH:MM:SS
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", local);

    if (params.verbose){
        printf("Timestamp: %s\n", timestamp);
    }
    else{
        printf("%s ", timestamp);
    }
    
}
