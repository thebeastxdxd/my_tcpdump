#ifndef __PCAP_FILE_H__
#define __PCAP_FILE_H__

#include <stdint.h>
#include "error.h"

typedef struct {
        uint32_t magic_number;
        uint16_t version_major;
        uint16_t version_minor;
        int32_t thiszone;
        uint32_t sigfigs;
        uint32_t snaplen;
        uint32_t network;
} pcap_hdr_t;


typedef struct {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
} pcaprec_hdr_t;

error_status_t open_pcap_file(const char* file_name, int* file_handle, uint32_t snaplen, uint32_t network_type);
error_status_t write_packet(int handle, unsigned char* packet_buf, size_t packet_len);
#endif // __PCAP_FILE_H__
