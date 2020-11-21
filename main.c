#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <argp.h>
#include "tcpdump.h"

static char doc[] = "my_tcpdump: a simple tcpdump implementation, for learning raw sockets.";
static char args_doc[] = "bpf";

typedef struct {
    char* output_file;
    char* interface;
} arguments_t;

static struct argp_option options[] = {
    {"write", 'w', "FILE", 0,    "pcap file to write to" },
    {"interface", 'i', "INTERFACE", 0, "interface to bind on" },
    //add bpf?
    //maybe add seconds to sniff
};


static error_t parse_opt (int key, char* arg, struct argp_state* state) {

    arguments_t* arguments = state->input;

    switch(key) {
        case 'w':
            arguments->output_file = arg;
            break;
        case 'i':
            arguments->interface = arg;
            break;
        case ARGP_KEY_END:
            break;
        default:
            return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

static struct argp argp = { options, parse_opt, args_doc, doc };

int main(int argc, char** argv) {

    arguments_t arguments = {0};
    struct sigaction sigint_act = {0};
    sigint_act.sa_handler = sigint_handler;
    sigaction(SIGINT, &sigint_act, NULL);
    
    // Default values 
    arguments.output_file = NULL;
    arguments.interface = NULL;
    
    argp_parse(&argp, argc, argv, 0, 0, &arguments);

    printf("interface=%s output_file=%s\n", arguments.interface, arguments.output_file);
    my_tcpdump(arguments.interface);

    return 0;

}
