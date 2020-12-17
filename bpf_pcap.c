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
    
    CHECK_STR(if_name_len <= sizeof(ifr.ifr_name), "Interface name too long");
    memcpy(ifr.ifr_name, if_name, if_name_len);

    // ioctl for getting hardware address
    CHECK(ioctl(sock, SIOCGIFHWADDR, &ifr) != -1);

    *link_type = ifr.ifr_hwaddr.sa_family;

cleanup:
    close(sock); // Best effort.
    return ret_status;
}

error_status_t bpf_program_to_sock_fprog(struct bpf_program* _bpf, struct sock_fprog* bpf_filter) {
    error_status_t ret_status = STATUS_SUCCESS;
    const struct bpf_insn* ins = NULL;
    struct sock_filter* out = NULL;
    int i = 0;
    

    CHECK(_bpf != NULL);
    CHECK(bpf_filter != NULL);

    bpf_filter->len = _bpf->bf_len;
    bpf_filter->filter = malloc(bpf_filter->len * sizeof(struct sock_filter));
    CHECK(bpf_filter->filter != NULL);

    for (i = 0, ins = _bpf->bf_insns, out = bpf_filter->filter; i < _bpf->bf_len; ++i, ++ins, ++out) {
        out->code = ins->code;
        out->jt = ins->jt;
        out->jf = ins->jf;
        out->k = ins->k;
    }

cleanup:
    return ret_status;
}

error_status_t compile_bpf(int snaplen, int link_type, struct sock_fprog* bpf_filter, const char* bpf_str, int opt) {
    error_status_t ret_status = STATUS_SUCCESS;
    struct bpf_program _bpf = {0};

    CHECK(bpf_filter != NULL);
    CHECK(bpf_str != NULL);

    // netmask - is the IPv4 netmask of the network, for checking Ipv4 broadcast packets.
    // tcpdump -ddd passes 0 to netmask so i feel comfortable doing it too.
    CHECK_STR(pcap_compile_nopcap(snaplen, link_type, &_bpf, bpf_str, opt, (bpf_u_int32)0) != -1, "Unable to compile give BPF");
    CHECK_FUNC(bpf_program_to_sock_fprog(&_bpf, bpf_filter));

cleanup:
    pcap_freecode(&_bpf); // Best effort.
    return ret_status;
}

void dump_bpf(struct sock_fprog* bpf_filter, int option) {

    struct sock_filter* out = NULL;
    int i = 0;

	switch(option){
		case 2:
			for (i = 0, out = bpf_filter->filter; i < bpf_filter->len; ++i, ++out) {
				printf("{ 0x%x, %d, %d, 0x%08x },\n",
						out->code, out->jt, out->jf, out->k);
			}
			break;
		case 3:
			printf("%d\n", bpf_filter->len);
			for (i = 0, out = bpf_filter->filter; i < bpf_filter->len; ++i, ++out) {
				printf("%u %u %u %u\n",
						out->code, out->jt, out->jf, out->k);
			}
			break;
		default:
			printf("%d not a valid option\n", option);
	}
}
