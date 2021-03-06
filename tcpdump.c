#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/filter.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if_arp.h>

#include "error.h"
#include "bpf_pcap.h"

// TODO: things i'm not sure about:
// 1. after create_raw_socket should i pass the sock_fd or a pointer to the sock_fd (right now its sock_fd)
// 2. if a CHECK fails should i close the socket in that function or in 
// an upper function(the function that create the socket)
// 3. how do i create a good CHECK with custom error message? should i just pass the error message?

// TODO: doc why this size
#define BUF_SIZE (65537)
// TODO: this is kinda random
#define MAX_BPF_LEN (50)

static bool running = true;

void sigint_handler(int sig) {

	running = false;
    return;

}

static error_status_t set_bpf(int sock, const char* bpf_str, int opt) {
    error_status_t ret_status = STATUS_SUCCESS;
    struct sock_fprog bpf_filter = {0};
    struct sock_filter* bpf_buffer = NULL;
    
    CHECK(sock != -1);
    CHECK(bpf_str != NULL);

    bpf_buffer = malloc(sizeof(struct sock_filter) * MAX_BPF_LEN);
    CHECK(bpf_buffer != NULL);

    bpf_filter.filter =  bpf_buffer;

    CHECK_FUNC(compile_bpf(BUF_SIZE, &bpf_filter, bpf_str, opt));

    // for debug purpose
    dump_bpf(&bpf_filter, 2); 
    CHECK(setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &bpf_filter, sizeof(bpf_filter)) >= 0);

cleanup:
    free(bpf_buffer); // Best effort.
    return ret_status;
}

static error_status_t iface_name_to_index(int sock, const char* if_name, int* if_index) {
    error_status_t ret_status = STATUS_SUCCESS;
    struct ifreq ifr = {0};
    size_t if_name_len = 0;

    CHECK(if_name != NULL);
    CHECK(if_index != NULL);
    
    if_name_len = strlen(if_name);

    // TODO: print interface name to long
    CHECK(if_name_len < sizeof(ifr.ifr_name));
    memcpy(ifr.ifr_name, if_name, if_name_len);

    // ioctl for mapping if_name to if_index
    CHECK(ioctl(sock, SIOCGIFINDEX, &ifr) != -1);
    
    *if_index = ifr.ifr_ifindex;

cleanup:
    return ret_status;
}

static error_status_t iface_set_promisc(int sock, const char* if_name, bool set) {
    error_status_t ret_status = STATUS_SUCCESS;
    int if_index = -1;
    int opt_name = -1;
    struct packet_mreq mreq = {0};
    
    CHECK(if_name != NULL);
    CHECK_FUNC(iface_name_to_index(sock, if_name, &if_index));

    mreq.mr_ifindex = if_index;
    mreq.mr_type = PACKET_MR_PROMISC;

	opt_name = set ? PACKET_ADD_MEMBERSHIP : PACKET_DROP_MEMBERSHIP;
    CHECK(setsockopt(sock, SOL_PACKET, opt_name, &mreq, sizeof(mreq)) != -1);

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

    // TODO: print was not able to bind to interface and show errno string
    CHECK(bind(sock, (struct sockaddr*)&sll, sizeof(sll)) >= 0);

cleanup:
    // TODO: i don't close here even if it fails because i want main func to close it? 
    //close(sock);
    return ret_status;

}

static error_status_t create_raw_socket(int* res) {
    error_status_t ret_status = STATUS_SUCCESS;
    int sock = -1;
    
    CHECK(res != NULL);

    sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    // TODO: print cannot create raw socket
    CHECK(sock >= 0);

    *res = sock;
cleanup:
    // TODO: i don't close here even if it fails because i want main func to close it? 
    //close(sock);
    return ret_status;
}
static error_status_t handle_packet(unsigned char* packet) {
    error_status_t ret_status = STATUS_SUCCESS;
    
    CHECK(packet != NULL);


    struct ethhdr* eth_h = (struct ethhdr*)packet;
	printf("Ethernet Header\n");
	printf("\t|-Source Address : %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n", eth_h->h_source[0],eth_h->h_source[1],eth_h->h_source[2],
   		eth_h->h_source[3],eth_h->h_source[4],eth_h->h_source[5]);
	printf("\t|-Destination Address : %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n", eth_h->h_dest[0],eth_h->h_dest[1],eth_h->h_dest[2],
   		eth_h->h_dest[3],eth_h->h_dest[4],eth_h->h_dest[5]);
cleanup:
    return ret_status;
}

static error_status_t sniff(int sock) {
    error_status_t ret_status = STATUS_SUCCESS;
    struct sockaddr_ll sll = {0};
    socklen_t sll_len = sizeof(sll);
    unsigned char buffer[BUF_SIZE] = {0};
    size_t r_bytes = 0;

    while(running) {
        r_bytes = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr*)&sll, &sll_len);
        // TODO: print error in reading recvfrom
        //CHECK(r_bytes >= 0);
        // TODO: print frame too large
        // TODO: is this the best way to handle this?
        // the problem here is that when we SIGINT recv terminates,
        // we want to handle this without CHECKing as it goes into cleanup.
        if ( r_bytes == -1 ) {
            if (errno == EINTR) {
                continue;
            }
        } 
        CHECK(r_bytes < sizeof(buffer));
        

        // printf("sockaddr info \n");
        // TODO: print sockaddr info?
        
        handle_packet((unsigned char*)&buffer);
    }

cleanup:
    return ret_status;
}

error_status_t my_tcpdump(const char* if_name, const char* bpf) {
    error_status_t ret_status = STATUS_SUCCESS;
    int raw_sock = -1;

	// TODO: add logic if if_name is NULL
    CHECK_FUNC(create_raw_socket(&raw_sock));
    CHECK_FUNC(bind_raw_socket(raw_sock, if_name));
    CHECK_FUNC(iface_set_promisc(raw_sock, if_name, true));
    // TODO: maybe this should be in iface_set_promisc; but it feels like a side effect?
    printf("set interface: %s to promisc\n", if_name);

    CHECK_FUNC(set_bpf(raw_sock, bpf, 1));
	CHECK_FUNC(sniff(raw_sock));


cleanup:
    // TODO: i cant CHECK this close because its in cleanup and this can cause a loop, what do i do?
    iface_set_promisc(raw_sock, if_name, false); // Best effort.
	close(raw_sock); // Best effort.
    return ret_status;
}
