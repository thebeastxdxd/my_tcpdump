#ifndef __BPF_PCAP_H__
#define __BPF_PCAP_H__

#include <linux/filter.h>
#include <pcap.h>
#include "error.h"

/**
 * @brief gets the link_type of a device
 *
 * @param if_name the device name
 * @param link_type output variable for string type
 *
 * @return standard error_status_t
 */
error_status_t dev_get_iftype(const char* if_name, int* link_type);

/**
 * @brief A function which converts a compiled bpf from bpf_program to sock_fprog
 * 
 * IMPORTANT: This function allocates bpf_filter and it is up to the caller of the function to 
 * deallocate the struct
 * @param _bpf the input bpf_program
 * @param bpf_filter the output sock_fprog
 *
 * @return standard error_status_t 
 */
error_status_t bpf_program_to_sock_fprog(struct bpf_program* _bpf, struct sock_fprog* bpf_filter);

/**
 * @brief A function that uses pcap to compile a bpf string
 *
 * this function uses the pcap library to compile our bpf string
 *
 * @param snaplen the maximum size of a returned a packet
 * @param link_type an int which holds the link type of our socket
 *
 * DLT_EN10MB is for ethernet, there is also DLT_NULL for BSD
 * loopback encapsulation.
 * @param bpf_filter ouput struct which will hold our compiled bpf
 * @param bpf_str a char* holding a string reprsentation of bpf
 * @param opt bool bool representing if pcap should optimize our bpf
 *
 * @return standard error_status_t
 */
error_status_t compile_bpf(int snaplen, int link_type, struct sock_fprog* bpf_filter, const char* bpf_str, int opt);

/**
 * @brief this function prints the bpf filter in a specifed format 
 *
 *
 * @param bpf_filter the filter
 * @param option int which chooses the output format
 *
 * option == 3 -> a decimal representing of the filter
 * option == 2 -> a c struct representation, this is a how the filter would look in code
 */
void dump_bpf(struct sock_fprog* bpf_filter, int option);

#endif // __BPF_PCAP_H__
