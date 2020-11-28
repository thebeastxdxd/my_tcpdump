#include <pcap.h>
#include <linux/filter.h>
#include <pcap/dlt.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <net/if.h>

#include "error.h"
 

error_status_t dev_get_iftype(const char* if_name, int* link_type) {
    error_status_t ret_status = STATUS_SUCCESS;
    int sock = -1;
    struct ifreq ifr = {0};
    size_t if_name_len = 0;

    CHECK(if_name != NULL);
    CHECK(link_type != NULL);

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    CHECK(sock >= 0);

    if_name_len = strlen(if_name);
    
    CHECK(if_name_len < IFNAMSIZ);
    memcpy(ifr.ifr_name, if_name, if_name_len);

    // ioctl for getting hardware address
    CHECK(ioctl(sock, SIOCGIFHWADDR, &ifr) != -1);

    *link_type = ifr.ifr_hwaddr.sa_family;

cleanup:
    close(sock); // Best effort.
    return ret_status;
}

error_status_t compile_bpf(int snaplen, struct sock_fprog* bpf_filter, const char* bpf_str, int opt) {
    // snaplen is  the maximum amount of data to be captured
    // linkytpe is the link layer type? DLT_EN10MB is for ethernet, there is also DLT_NULL for BSD
    // loopback encapsulation.
    // netmask - is the IPv4 netmask of the network, for checking Ipv4 broadcast packets.
    // tcpdump -ddd passes 0 to netmask so i feel comfortable doing it too.
    error_status_t ret_status = STATUS_SUCCESS;
    struct bpf_program _bpf = {0};
    const struct bpf_insn* ins = NULL;
    struct sock_filter* out = NULL;
    int i = 0;
    

    CHECK(bpf_filter != NULL);
    CHECK(bpf_filter->filter != NULL);
    CHECK(bpf_str != NULL);

    // TODO: print compiling failed.
    // TODO: get correct linktype using dev_get_iftype
    CHECK(pcap_compile_nopcap(snaplen, DLT_EN10MB, &_bpf, bpf_str, opt, (bpf_u_int32)0) != -1);
    
    bpf_filter->len = _bpf.bf_len;
    bpf_filter->filter = realloc(bpf_filter->filter, bpf_filter->len * sizeof(struct sock_filter));
    CHECK(bpf_filter->filter != NULL);

    // TODO: should this be in a different function?
    for (i = 0, ins = _bpf.bf_insns, out = bpf_filter->filter; i < _bpf.bf_len; ++i, ++ins, ++out) {
        out->code = ins->code;
        out->jt = ins->jt;
        out->jf = ins->jf;
        out->k = ins->k;
        
        // TODO: figure this out
        /* this was taken from netsniff-ng, but i don't know why they do this
        if (out->code == 0x06 && out->k > 0) {
            out->k = 0xFFFFFFFF;
        }
        */
    }

cleanup:
    pcap_freecode(&_bpf); // Best effort.
    return ret_status;
}

void dump_bpf(struct sock_fprog* bpf_filter, int option) {

    struct sock_filter* out = NULL;
    int i = 0;
    if (option > 2) { 
        printf("%d\n", bpf_filter->len);
        for (i = 0, out = bpf_filter->filter; i < bpf_filter->len; ++i, ++out) {
            printf("%u %u %u %u\n",
                    out->code, out->jt, out->jf, out->k);
        }
    } else if (option > 1 ){
        for (i = 0, out = bpf_filter->filter; i < bpf_filter->len; ++i, ++out) {
            printf("{ 0x%x, %d, %d, 0x%08x },\n",
                    out->code, out->jt, out->jf, out->k);
        }
    }
    else {
        printf("%d not a valid option\n", option);
    }
}
