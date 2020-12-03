/* important repos that helped me
 * tcpdump
 * libpcap
 * tklauser/filter2xdp
 * netsniff-ng/netsniff-ng
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <argp.h>
#include "tcpdump.h"


// TODO:
// 1. clean this up, its nasty!
// 2. should i add CHECK to function in main?
// 3. implement all the flags cool flags

// TODO: fix, this is kinda random
#define MAX_BPF_STR_LEN (512)

static char *cat(char *dest, const char *end, const char *str) {

    while (dest < end && *str != '\0')
        *dest++ = *str++;
    
    // str too long
    if (dest == end && *str != '\0')
        return NULL;

    return dest;

}

static int create_bpf_exp(char* bpf_buf, int bpf_max_len, char** bpf_argv, int bpf_argv_len) {
    char* p_bpf = bpf_buf;
    char* p_bpf_end = bpf_buf + bpf_max_len;
    int i = 0;

    printf("%d\n", bpf_argv_len);
    while (p_bpf < p_bpf_end && i < bpf_argv_len) {
        p_bpf = cat(p_bpf, p_bpf_end, bpf_argv[i]);    
        if (p_bpf == NULL) 
            return -1;

        i += 1;
        if (i < bpf_argv_len)
            p_bpf = cat(p_bpf, p_bpf_end, " ");
            if (p_bpf == NULL) 
                return -1;
    }

    memset(p_bpf, '\0', (p_bpf_end - p_bpf));
    return 0;
}

typedef struct {
    char* output_file;
    char* interface;
    char** bpf;
    int bpf_len;
} arguments_t;


static char doc[] = "my_tcpdump: a simple tcpdump implementation, for learning raw sockets.";
static char args_doc[] = "bpf";
static struct argp_option options[] = {
    {"write", 'w', "FILE", 0,    "pcap file to write to" },
    {"interface", 'i', "INTERFACE", 0, "interface to bind on" },
    // TODO: maybe add seconds to sniff
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
        case ARGP_KEY_ARGS:
            arguments->bpf = state->argv + state->next;
            arguments->bpf_len = state->argc - state->next;
            break;
        case ARGP_KEY_END:
            // TODO: am i supposed to do something here?
            break;
        default:
            return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

static struct argp argp = { options, parse_opt, args_doc, doc };

int main(int argc, char** argv) {

    int ret = 0;
    arguments_t arguments = {0};
    char bpf_buf[MAX_BPF_STR_LEN] = {0};
    struct sigaction sigint_act = {0};
    sigint_act.sa_handler = sigint_handler;

    sigaction(SIGINT, &sigint_act, NULL);
    
    // Default values 
    arguments.output_file = NULL;
    arguments.interface = NULL;
    arguments.bpf = NULL;
    arguments.bpf_len = 0;
    
    argp_parse(&argp, argc, argv, 0, 0, &arguments);

    ret = create_bpf_exp(bpf_buf, MAX_BPF_STR_LEN, arguments.bpf, arguments.bpf_len);
    if (ret == -1) {
        printf("bpf too long!\n");
        return -1;
    }

    printf("interface=%s, output_file=%s, bpf=%s\n", arguments.interface, arguments.output_file, bpf_buf);
    ret = my_tcpdump(arguments.interface, arguments.output_file, bpf_buf);

    return ret;

}
