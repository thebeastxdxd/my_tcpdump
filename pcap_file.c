#include <sys/time.h>
#include <fcntl.h>
#include <stdint.h>
#include <unistd.h>

#include "pcap_file.h"
#include "error.h"

error_status_t open_pcap_file(const char* file_name, int* fd, uint32_t snaplen,
                              uint32_t network_type) {
    error_status_t ret_status = STATUS_SUCCESS;
    pcap_hdr_t file_header = {0};
    int _fd = -1;
    ssize_t w_bytes = -1;

    CHECK(file_name != NULL);
    CHECK(fd != NULL);

    _fd = open(file_name, O_CREAT | O_RDWR | O_TRUNC, 644);
    CHECK(_fd != -1);

    file_header.magic_number = PCAP_MAGIC_NUMBER;
    file_header.version_major = PCAP_MAJOR_VERSION;
    file_header.version_minor = PCAP_MINOR_VERSION;
    // ignoring time stuff
    file_header.thiszone = 0;
    file_header.sigfigs = 0;
    file_header.snaplen = snaplen;
    file_header.network = network_type;

    w_bytes = write(_fd, &file_header, sizeof(pcap_hdr_t));
    CHECK(w_bytes == sizeof(pcap_hdr_t));

    *fd = _fd;

cleanup:
    return ret_status;
}

error_status_t write_packet(int fd, unsigned char* packet_buf,
                            size_t packet_len, struct timeval* ts) {
    error_status_t ret_status = STATUS_SUCCESS;
    pcaprec_hdr_t packet_hdr = {0};
    ssize_t w_bytes = -1;

    CHECK(fd != -1);
    CHECK(packet_buf != NULL);
    CHECK(ts != NULL);

    packet_hdr.ts_sec = ts->tv_sec;
    packet_hdr.ts_usec = ts->tv_usec;
    packet_hdr.incl_len = packet_len;
    packet_hdr.orig_len = packet_len;

    w_bytes = write(fd, &packet_hdr, sizeof(pcaprec_hdr_t));
    CHECK(w_bytes == sizeof(pcaprec_hdr_t));
    w_bytes = write(fd, packet_buf, packet_len);
    CHECK(w_bytes == packet_len);

cleanup:
    return ret_status;
}
