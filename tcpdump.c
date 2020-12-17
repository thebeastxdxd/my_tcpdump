#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/filter.h>
#include <linux/bpf_common.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if_arp.h>
#include <pcap/dlt.h>

#include "error.h"
#include "bpf_pcap.h"
#include "pcap_file.h"

// linux MTU (including loopback interface) defaults to 65536
// to handle MSG_TRUNC without using recvmsg (and creating msghdr struct) we define the
// size to be 1 byte bigger and check if a recieved packet is equal to MAX_PKT_LEN
// snapshot len should then be MAX_PKT_LEN -1 
#define MAX_PKT_LEN (65537)

static bool running = true;

void sigint_handler(int sig) {

    running = false;
    return;

}

static error_status_t set_bpf(int sock, int link_type, const char* bpf_str, int opt) {
    error_status_t ret_status = STATUS_SUCCESS;
    struct sock_fprog bpf_filter = {0};
    
    CHECK(sock != -1);
    CHECK(bpf_str != NULL);

    CHECK_FUNC(compile_bpf(MAX_PKT_LEN - 1, link_type, &bpf_filter, bpf_str, opt));

#ifdef DEBUG
    dump_bpf(&bpf_filter, 2); 
#endif
    CHECK(setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &bpf_filter, sizeof(bpf_filter)) >= 0);

cleanup:
    free(bpf_filter.filter); // Best effort.
    return ret_status;
}

static error_status_t iface_name_to_index(int sock, const char* if_name, int* if_index) {
    error_status_t ret_status = STATUS_SUCCESS;
    struct ifreq ifr = {0};
    size_t if_name_len = 0;

    CHECK(sock != -1);
    CHECK(if_name != NULL);
    CHECK(if_index != NULL);
    
    if_name_len = strlen(if_name);

    CHECK_STR(if_name_len <= sizeof(ifr.ifr_name), "Interface name too long");
    memcpy(ifr.ifr_name, if_name, if_name_len);
    // ioctl for mapping if_name to if_index
    CHECK(ioctl(sock, SIOCGIFINDEX, &ifr) != -1);

    *if_index = ifr.ifr_ifindex;

cleanup:
    return ret_status;
}

static error_status_t iface_get_promisc(int sock, const char* if_name, bool* if_state) {
    error_status_t ret_status = STATUS_SUCCESS;
    struct ifreq ifr = {0};
    size_t if_name_len = 0;

    CHECK(sock != -1);
    CHECK(if_name != NULL);
    CHECK(if_state != NULL);
    
    if_name_len = strlen(if_name);

    CHECK_STR(if_name_len <= sizeof(ifr.ifr_name), "Interface name too long");
    memcpy(ifr.ifr_name, if_name, if_name_len);

    // ioctl for getting interface flags
    CHECK(ioctl(sock, SIOCGIFFLAGS, &ifr) != -1);
    
    *if_state = (bool)(ifr.ifr_flags & IFF_PROMISC);

cleanup:
    return ret_status;
}

static error_status_t set_packet_timestamp(int sock, bool enable) {
    error_status_t ret_status = STATUS_SUCCESS;
    int e = 0;

    CHECK(sock != -1);
    
    e = enable ? 1 : 0;
    CHECK(setsockopt(sock, SOL_SOCKET, SO_TIMESTAMP, &e, sizeof(e)) != -1);

cleanup:
    return ret_status;
}

static error_status_t iface_set_promisc(int sock, const char* if_name, bool set) {
    error_status_t ret_status = STATUS_SUCCESS;
    int if_index = -1;
    int opt_name = -1;
    struct packet_mreq mreq = {0};
    
    CHECK(sock != -1);
    CHECK(if_name != NULL);
    CHECK_FUNC(iface_name_to_index(sock, if_name, &if_index));

    mreq.mr_ifindex = if_index;
    mreq.mr_type = PACKET_MR_PROMISC;

	opt_name = set ? PACKET_ADD_MEMBERSHIP : PACKET_DROP_MEMBERSHIP;
    CHECK(setsockopt(sock, SOL_PACKET, opt_name, &mreq, sizeof(mreq)) != -1);
    printf("set interface: %s to promisc %d\n", if_name, set);

cleanup:
    return ret_status;
}

static error_status_t bind_raw_socket(int sock, const char* if_name) {
    error_status_t ret_status = STATUS_SUCCESS;
    int if_index = -1;
    struct sockaddr_ll sll = {0};
    
    CHECK(if_name != NULL);
    CHECK_FUNC(iface_name_to_index(sock, if_name, &if_index));

    // to bind a raw socket to a specific interface 
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = if_index;

    CHECK_STR(bind(sock, (struct sockaddr*)&sll, sizeof(sll)) >= 0, "Failed binding to interface");

cleanup:
    return ret_status;
}

static error_status_t create_raw_socket(int* res) {
    error_status_t ret_status = STATUS_SUCCESS;
    int sock = -1;
    
    CHECK(res != NULL);

    sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    CHECK_STR(sock >= 0, "Creating raw socket failed");

    *res = sock;
cleanup:
    return ret_status;
}

static error_status_t handle_packet(unsigned char* packet, int packet_len) {
    error_status_t ret_status = STATUS_SUCCESS;
    
    CHECK(packet != NULL);

    // Basic packet parser
    // add more: ip level, tcp/udp, blah blah
    CHECK(packet_len > sizeof(struct ethhdr));

    struct ethhdr* eth_h = (struct ethhdr*)packet;
	printf("Ethernet Header\n");
	printf("\t|-Source Address : %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n", eth_h->h_source[0],eth_h->h_source[1],eth_h->h_source[2],
   		eth_h->h_source[3],eth_h->h_source[4],eth_h->h_source[5]);
	printf("\t|-Destination Address : %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n", eth_h->h_dest[0],eth_h->h_dest[1],eth_h->h_dest[2],
   		eth_h->h_dest[3],eth_h->h_dest[4],eth_h->h_dest[5]);

cleanup:
    return ret_status;
}

static error_status_t sniff(int sock, int fd) {
    error_status_t ret_status = STATUS_SUCCESS;
    struct msghdr msg = {0};
    struct iovec iov[1] = {0};
    union {
        char control[CMSG_SPACE(sizeof(struct timeval))];
        struct cmsghdr align;
    } u;
    struct cmsghdr* cmsg = NULL;
    struct timeval* ts = NULL;
    struct sockaddr_ll sll = {0};
    unsigned char buffer[MAX_PKT_LEN] = {0};
    ssize_t r_bytes = 0;

    CHECK(sock != -1);

    iov[0].iov_base = buffer;
    iov[0].iov_len = MAX_PKT_LEN;

    msg.msg_name = &sll;
    msg.msg_namelen = sizeof(sll);
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;
    msg.msg_control = u.control;
    msg.msg_controllen = sizeof(u.control);


    while (running) {
        r_bytes = recvmsg(sock, &msg, 0);
        // check if recieved packet is too long.
        if (msg.msg_flags & MSG_TRUNC) {
            printf("Packet len too long: %ld bytes\n", r_bytes);
            continue;
        }

        // EINTR should be handled gracefully, because of sig_handler, 
        // every other ERR should fail.
        if (r_bytes == -1) {
            CHECK_STR(errno == EINTR, "Error While recieving.");
            continue;
        }
        
        for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL; cmsg=CMSG_NXTHDR(&msg, cmsg)) {
            if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SO_TIMESTAMP) {
                ts = (struct timeval*)CMSG_DATA(cmsg); 
                break;
            }
        }
        // TODO: print sockaddr info?
        if (fd != -1) {
            write_packet(fd, buffer, r_bytes, ts);
        } else {
            handle_packet(buffer, r_bytes);
        }
    }

cleanup:
    return ret_status;
}

error_status_t my_tcpdump(const char* if_name, const char* output_file, const char* bpf) {
    error_status_t ret_status = STATUS_SUCCESS;
    int raw_sock = -1;
    int fd = -1;
    int link_type = -1;
    bool promisc_state = false;
    
    CHECK_FUNC(create_raw_socket(&raw_sock));

    if (if_name != NULL) {
        CHECK_FUNC(bind_raw_socket(raw_sock, if_name));
        //CHECK_FUNC(iface_get_promisc(raw_sock, if_name, &promisc_state));
        CHECK_FUNC(iface_set_promisc(raw_sock, if_name, true));
        CHECK_FUNC(dev_get_iftype(if_name, &link_type));
    } else {
        // linux cooked mode, a pseudo-protocol for handeling capture from "any" device.
        link_type = DLT_LINUX_SLL;
    }

    if (output_file != NULL) {
      CHECK_FUNC(open_pcap_file(output_file, &fd, MAX_PKT_LEN - 1, link_type));
    }
    if (strlen(bpf) != 0) {
        CHECK_FUNC(set_bpf(raw_sock, 
                           link_type,
                           bpf,
                           1 // Optimize the BPF
                           ));
    }
    CHECK_FUNC(set_packet_timestamp(raw_sock, true));
    CHECK_FUNC(sniff(raw_sock, fd));

cleanup:
    if (if_name != NULL) {
        if(iface_set_promisc(raw_sock, if_name, false) != 0) {
            // Best effort.
            printf("[IMPORTANT] failed to decrement promisc state\n");
        }
    }
	close(raw_sock); // Best effort.
    close(fd); // Best effort.
    return ret_status;
}
