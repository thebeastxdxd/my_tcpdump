#include <fcntl.h>
#include <stdint.h>
#include <unistd.h>

#include "pcap_file.h"
#include "error.h"

error_status_t open_pcap_file(const char *file_name, int* file_handle, uint32_t snaplen,
                              uint32_t network_type) {
    error_status_t ret_status = STATUS_SUCCESS;
    pcap_hdr_t file_header = {0};
    int handle = -1;
    ssize_t r_bytes = -1;

    CHECK(file_name != NULL);
    CHECK(file_handle != NULL);

    handle = open(file_name, O_CREAT | O_RDWR | O_TRUNC, 644);
    CHECK(handle != -1);

    // pcap magic number
    file_header.magic_number = 0xa1b2c3d4;
    // current file format version
    file_header.version_major = 2;
    file_header.version_minor = 4;
    // ignoring time stuff
    file_header.thiszone = 0;
    file_header.sigfigs = 0;
    file_header.snaplen = snaplen;
    file_header.network = network_type;

    r_bytes = write(handle, &file_header, sizeof(pcap_hdr_t));
    CHECK((r_bytes != -1) && (r_bytes == sizeof(pcap_hdr_t)));

    *file_handle = handle; 

cleanup:
    return ret_status;
}

error_status_t write_packet(int handle, unsigned char* packet_buf, size_t packet_len) {
    error_status_t ret_status = STATUS_SUCCESS;
    pcaprec_hdr_t packet_hdr = {0};
    ssize_t r_bytes = -1;

    CHECK(handle != -1);
    CHECK(packet_buf != NULL);
    
    // TODO: give packet time info
    packet_hdr.ts_sec = 0;
    packet_hdr.ts_usec = 0;
    packet_hdr.incl_len = packet_len;
    packet_hdr.orig_len = packet_len;

    r_bytes = write(handle, &packet_hdr, sizeof(pcaprec_hdr_t));
    CHECK((r_bytes != -1) && (r_bytes == sizeof(pcaprec_hdr_t)));
    r_bytes = write(handle, packet_buf, packet_len);
    CHECK((r_bytes != -1) && (r_bytes == packet_len));

cleanup:
    return ret_status;

}
