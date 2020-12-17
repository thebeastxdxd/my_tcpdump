#ifndef __PCAP_FILE_H__
#define __PCAP_FILE_H__

#include <stdint.h>
#include <sys/time.h>
#include "error.h"


#define PCAP_MAGIC_NUMBER (0xa1b2c3d4)
#define PCAP_MAJOR_VERSION (2)
#define PCAP_MINOR_VERSION (4)

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

error_status_t open_pcap_file(const char* file_name, int* fd, uint32_t snaplen, uint32_t network_type);
error_status_t write_packet(int fd, unsigned char* packet_buf, size_t packet_len, struct timeval* ts);
#endif // __PCAP_FILE_H__
