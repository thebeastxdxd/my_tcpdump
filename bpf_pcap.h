#ifndef __BPF_PCAP_H__
#define __BPF_PCAP_H__

#include "error.h"
#include <linux/filter.h>

error_status_t compile_bpf(int snaplen, struct sock_fprog* bpf_filter, const char* bpf_str, int opt);
error_status_t dev_get_iftype(const char* if_name, int* link_type);
void dump_bpf(struct sock_fprog* bpf_filter, int option);

#endif // __BPF_PCAP_H__
