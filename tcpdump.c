#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include "error.h"

// TODO: figure out if you want to give res(pointer to fd) as a parameter or sock (fd)

#define IFACE ("eth0")
//TODO: is this the correct size?
#define BUF_SIZE (65537)

static error_status_t iface_name_to_index(int* res, const char* if_name, int* if_index) {
    error_status_t ret_status = SUCCESS_STATUS;
    int sock = -1;
    struct ifreq ifr = {0};
    size_t if_name_len = 0;

    CHECK(res != NULL);
    CHECK(if_name != NULL);
    CHECK(if_index != NULL);
    
    sock = *res;
    if_name_len = strlen(if_name);

    // TODO: print interface name to long
    CHECK(if_name_len < sizeof(ifr.ifr_name));
    memcpy(ifr.ifr_name, if_name, if_name_len);

    // ioctl for mapping if_name to if_index
    CHECK(ioctl(sock, SIOCGIFINDEX, &ifr) != -1);

    *if_index = ifr.ifr_ifindex;
    return ret_status;

cleanup:
    *if_index = -1;
    return ret_status;
}

static error_status_t iface_set_promisc(int* res, int if_index, int set) {
    error_status_t ret_status = SUCCESS_STATUS;
    int sock = -1;
    struct packet_mreq mreq = {0};
    int opt_name = -1;
    
    CHECK(res != NULL);
    sock = *res;
    mreq.mr_ifindex = if_index;
    mreq.mr_type = PACKET_MR_PROMISC;

    // TODO: is this ugly?
    if (set) {
        opt_name = PACKET_ADD_MEMBERSHIP;
    }
    else {
        opt_name = PACKET_DROP_MEMBERSHIP;
    }

    CHECK(setsockopt(sock, SOL_PACKET, opt_name, &mreq, sizeof(mreq)) != -1);

cleanup:
    return ret_status;
}

static error_status_t bind_raw_socket(int* res, const char* if_name) {
    error_status_t ret_status = SUCCESS_STATUS;
    int sock = -1;
    int if_index = -1;
    struct sockaddr_ll sll = {0};
    
    CHECK(res != NULL);
    CHECK(if_name != NULL);

    sock = *res;
    CHECK(iface_name_to_index(&sock, if_name, &if_index) == SUCCESS_STATUS);

    // to bind a raw socket to a specific interface 
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = if_index;

    // TODO: print was not able to bind to interface and show errno string
    CHECK(bind(sock, (struct sockaddr*)&sll, sizeof(sll)) >= 0);

    return ret_status;
cleanup:
    close(sock);
    res = NULL;
    return ret_status;

}

static error_status_t create_raw_socket(int* res) {
    error_status_t ret_status = SUCCESS_STATUS;
    int sock = -1;
    
    CHECK(res != NULL);

    sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    // TODO: print cannot create raw socket
    CHECK(sock >= 0);

    *res = sock;
    return ret_status;
cleanup:
    close(sock);
    res = NULL;
    return ret_status;
}

static error_status_t sniff(int* sock) {
    error_status_t ret_status = SUCCESS_STATUS;
    struct sockaddr_ll sll = {0};
    socklen_t sll_len = sizeof(sll);
    unsigned char buffer[BUF_SIZE] = {0};
    size_t r_bytes = 0;
    
    CHECK(sock != NULL);

    r_bytes = recvfrom(*sock, buffer, sizeof(buffer), 0, (struct sockaddr*)&sll, &sll_len);
    // TODO: print error in reading recvfrom
    CHECK(r_bytes >= 0);
    // if r_bytes == sizeof(buffer), frame too large
    
    printf("sockaddr info \n");

    struct ethhdr* eth_h = (struct ethhdr*)buffer;
	printf("Ethernet Header\n");
	printf("\t|-Source Address : %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n", eth_h->h_source[0],eth_h->h_source[1],eth_h->h_source[2],
   		eth_h->h_source[3],eth_h->h_source[4],eth_h->h_source[5]);
	printf("\t|-Destination Address : %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n", eth_h->h_dest[0],eth_h->h_dest[1],eth_h->h_dest[2],
   		eth_h->h_dest[3],eth_h->h_dest[4],eth_h->h_dest[5]);
cleanup:
    return ret_status;
}

error_status_t my_tcpdump() {
    error_status_t ret_status = SUCCESS_STATUS;
    int raw_sock = -1;
    int if_index = -1;

    CHECK(create_raw_socket(&raw_sock) == SUCCESS_STATUS);
    CHECK(bind_raw_socket(&raw_sock, IFACE) == SUCCESS_STATUS);
    CHECK(iface_name_to_index(&raw_sock, IFACE, &if_index) == SUCCESS_STATUS);
    CHECK(iface_set_promisc(&raw_sock, if_index, TRUE) == SUCCESS_STATUS);
    printf("set interface: %s to promisc\n", IFACE);
	CHECK(sniff(&raw_sock) == SUCCESS_STATUS);

    CHECK(iface_set_promisc(&raw_sock, if_index, FALSE) == SUCCESS_STATUS);
    printf("unset interface: %s to promisc\n", IFACE);
	close(raw_sock);
cleanup:
    return ret_status;
}
