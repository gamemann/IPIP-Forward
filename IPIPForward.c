#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if.h>
#include <linux/if_packet.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <net/ethernet.h>
#include <string.h>
#include <error.h>
#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <sys/sysinfo.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <ctype.h>

#define REDIRECT_HEADER

#include "csum.h"
#include "common.h"

extern int errno;

struct stuff
{
    char *lIP;
    uint16_t lPort;
    char *dIP;
    char *nIP;
    uint16_t dPort;
    int sendingSocket;
    char *interface;
};

void sigHndl(int tmp)
{
    // Set cont to 0 which will break while loops.
    cont = 0;
}

int forwardPacket(uint8_t protocol, char *buffer, int socket, int size, struct stuff *info)
{
    uint16_t sent;

    // Start new data buffer.
    char newData[MAX_PCKT_LENGTH];
    
    // Copy buffer to newData.
    memcpy(newData, buffer, MAX_PCKT_LENGTH);

    // Add outer IP header.
    shiftChar(newData + sizeof(struct ethhdr), sizeof(struct iphdr), size - sizeof(struct ethhdr));

    // Set ethernet header.
    struct ethhdr *ethhdr = (struct ethhdr *) (newData);

    // Set outer IP header.
    struct iphdr *out_iphdr = (struct iphdr *) (newData + sizeof(struct ethhdr));

    // Set inner IP header.
    struct iphdr *in_iphdr = (struct iphdr *) (newData + sizeof(struct ethhdr) + sizeof(struct iphdr));

    /* Ethernet header */

    // Replace source MAC address with the interface's MAC on forwarding machine.
    memcpy(ethhdr->h_source, srcMac, ETH_ALEN);

    // Replace destination MAC address with the router/gateway's MAC address that we got.
    memcpy(ethhdr->h_dest, routerMac, ETH_ALEN);

    /* Outer IP header */

    // We're using IPv4.
    out_iphdr->version = 4;

    // 5 x 4 (due to 32-bit words) = 20 bytes.
    out_iphdr->ihl = 5;

    // IPIP protocol.
    out_iphdr->protocol = IPPROTO_IPIP;

    // No fragment offset.
    out_iphdr->frag_off = 0;

    // Set checksum to 0.
    out_iphdr->check = 0;

    // Time-to-live is 64.
    out_iphdr->ttl = 64;

    // No specific Type Of Service.
    out_iphdr->tos = 0x0;

    // Set destination to server we're forwarding to.
    out_iphdr->daddr = inet_addr(info->dIP);

    // Set source to server we're forwarding from.
    out_iphdr->saddr = inet_addr(info->lIP);

    // Total length of outer IP header plus inner IP header, transport protocol header, and data in network byte order (htons).
    out_iphdr->tot_len = htons(ntohs(in_iphdr->tot_len) + sizeof(struct iphdr));

    // Perform quick checksum calculation.
    out_iphdr->check = ip_fast_csum(out_iphdr, out_iphdr->ihl);

    /* Inner IP header */

    // Save old inner IP header's destination address and swap.
    uint32_t oldDaddr = in_iphdr->daddr;
    in_iphdr->daddr = inet_addr(info->nIP);

    // Now recalulate checksum for inner IP header since that was changed. We're doing a quick recalculation.
    in_iphdr->check = csum_diff4(oldDaddr, in_iphdr->daddr, in_iphdr->check);

     /* Transport protocols */

    // Recalculate the checksum for each protocol.
    switch (protocol)
    {
        case IPPROTO_UDP:
        {
            struct udphdr *udphdr = (struct udphdr *) (newData + sizeof(struct ethhdr) + sizeof(struct iphdr) + (in_iphdr->ihl * 4));
            udphdr->check = csum_diff4(oldDaddr, in_iphdr->daddr, udphdr->check);
            
            break;
        }

        case IPPROTO_TCP:
        {
            struct tcphdr *tcphdr = (struct tcphdr *) (newData + sizeof(struct ethhdr) + sizeof(struct iphdr) + (in_iphdr->ihl * 4));
            tcphdr->check = csum_diff4(oldDaddr, in_iphdr->daddr, tcphdr->check);
            
            break;
        }

        case IPPROTO_ICMP:
        {
            struct icmphdr *icmphdr = (struct icmphdr *) (newData + sizeof(struct ethhdr) + sizeof(struct iphdr) + (in_iphdr->ihl * 4));
            icmphdr->checksum = csum_diff4(oldDaddr, in_iphdr->daddr, icmphdr->checksum);
            
            break;
        }
    }

    // Write packet to socket descriptor
    sent = write(socket, newData, ntohs(out_iphdr->tot_len) + sizeof(struct ethhdr));

    // Return sent (in bytes).
    return sent;
}

int replyToClient(uint8_t protocol, char *buffer, int socket, int size, struct stuff *info)
{
    uint16_t sent;

    // First, let's get the destination IP of the outer header and save that for later. This will represent the bind address.
    uint32_t bindAddr;
    struct iphdr *out_iphdr = (struct iphdr *) (buffer + sizeof(struct ethhdr));

    bindAddr = out_iphdr->daddr;

    // Let's remove the outer IP header. Since we know the outer IP header should be 20 bytes, we can just use sizeof(struct iphdr).
    removeChar(buffer + sizeof(struct ethhdr), sizeof(struct iphdr), size - sizeof(struct ethhdr) - sizeof(struct iphdr));

    // Initialize headers.
    struct ethhdr *ethhdr = (struct ethhdr *) (buffer);
    struct iphdr *iphdr = (struct iphdr *) (buffer + sizeof(struct ethhdr));

    /* Ethernet header */

    // Replace source MAC address with the interface's MAC on forwarding machine.
    memcpy(ethhdr->h_source, srcMac, ETH_ALEN);

    // Replace destination MAC address with the router/gateway's MAC address that we got.
    memcpy(ethhdr->h_dest, routerMac, ETH_ALEN);

    /* IP Header */

    // Save old IP header's source address and swap.
    uint32_t srcAddr = iphdr->saddr;
    iphdr->saddr = bindAddr;

    // Now recalulate checksum for IP header since that was changed. We're doing a quick recalculation.
    iphdr->check = csum_diff4(srcAddr, iphdr->saddr, iphdr->check);

    /* Transport protocols */

    // Recalculate the checksum for each protocol.
    switch (protocol)
    {
        case IPPROTO_UDP:
        {
            struct udphdr *udphdr = (struct udphdr *) (buffer + sizeof(struct ethhdr) + (iphdr->ihl * 4));
            udphdr->check = csum_diff4(srcAddr, iphdr->saddr, udphdr->check);
            
            break;
        }

        case IPPROTO_TCP:
        {
            struct tcphdr *tcphdr = (struct tcphdr *) (buffer + sizeof(struct ethhdr) + (iphdr->ihl * 4));
            tcphdr->check = csum_diff4(srcAddr, iphdr->saddr, tcphdr->check);
            
            break;
        }

        case IPPROTO_ICMP:
        {
            struct icmphdr *icmphdr = (struct icmphdr *) (buffer + sizeof(struct ethhdr) + (iphdr->ihl * 4));
            icmphdr->checksum = csum_diff4(srcAddr, iphdr->saddr, icmphdr->checksum);
            
            break;
        }
    }

    // Write packet to socket descriptor
    sent = write(socket, buffer, ntohs(iphdr->tot_len) + sizeof(struct ethhdr));

    // Return sent (in bytes).
    return sent;
}

void* threadHndl(void * data)
{
    // Turn data into stuff struct.
    struct stuff *stuff = data;

    // Create buffer.
    unsigned char buffer[MAX_PCKT_LENGTH];

    // Initialize sockfds. We also copy the sending socket fd to a new variable to prevent overwriting from all the threads (this was an issue I faced).
    int sockfd, sendsockfd = stuff->sendingSocket;

    // Set up receiving socket that processes all packets on a certain interface :)
    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));

    // Check for sockfd error.
    if (sockfd == -1)
    {
        fprintf(stderr, "Socket() :: Error - %s\n", strerror(errno));
        perror("socket");

        pthread_exit(NULL);
    }

    // Bind socket to interface.
    if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, stuff->interface, strlen(stuff->interface)) < 0)
    {
        fprintf(stderr, "SetSockOpt() :: Error %s\n", strerror(errno));
        perror("setsockopt");

        pthread_exit(NULL);
    }

    // Perform fanout on the AF_PACKET socket. This allows us to have multiple sockets for receiving all in the same group (e.g. one per thread).
    int fanout_arg;
    fanout_arg = (fanout_id | (PACKET_FANOUT_HASH << 16));

    if (setsockopt(sockfd, SOL_PACKET, PACKET_FANOUT, &fanout_arg, sizeof(fanout_arg)) < 0)
    {
        perror("setsockopt (fanout)");

        pthread_exit(NULL);
    }

    // Get thread ID.
    pthread_t threadID = pthread_self();

    //struct ethhdr *ethhdr = (struct ethhdr *) buffer;
    struct iphdr *iphdr = (struct iphdr *) (buffer + sizeof(struct ethhdr));

    // Set buffer to all 0's.
    memset(buffer, 0, MAX_PCKT_LENGTH);

    // Initialize the struct sockaddr_ll for receiving. Won't be used in this case.
    struct sockaddr_ll din;
    socklen_t dinLen = sizeof(din);

    while(cont)
    {
        // Receive packet.
        uint16_t received = recvfrom(sockfd, &buffer, MAX_PCKT_LENGTH, 0, (struct sockaddr *)&din, &dinLen);

        // Check protocol.
        if (iphdr->protocol == IPPROTO_TCP)
        {
            // Initialize TCP Header.
            struct tcphdr *tcphdr = (struct tcphdr *) (buffer + sizeof(struct ethhdr) + (iphdr->ihl * 4));

            // Check if destination is listen IP and port is above 1024. I plan to make it so it'll include all ports, but exclude specific ones in a config file. This wil lbe done in a program I plan to make at another time.
            if (iphdr->daddr == inet_addr(stuff->lIP) && ntohs(tcphdr->dest) > 1024)
            {
                // Forward packet.
                if (forwardPacket(IPPROTO_TCP, buffer, sendsockfd, received, stuff) < 0)
                {
                    perror("forwardPacket");
                }
            }

            // Increment packet count.
            packetCount++;
        }
        else if (iphdr->protocol == IPPROTO_UDP)
        {
            // Initialize UDP Header.
            struct udphdr *udphdr = (struct udphdr *) (buffer + sizeof(struct ethhdr) + (iphdr->ihl * 4));

            // Check if destination is listen IP and port is above 1024.
            if (iphdr->daddr == inet_addr(stuff->lIP) && ntohs(udphdr->dest) > 1024)
            {
                // Forward packet.
                if (forwardPacket(IPPROTO_UDP, buffer, sendsockfd, received, stuff) < 0)
                {
                    perror("forwardPacket");
                }
            }

            // Increment packet count.
            packetCount++;
        }
        else if (iphdr->protocol == IPPROTO_ICMP)
        {
            // Initialize ICMP Header.
            struct icmphdr *icmphdr = (struct icmphdr *) (buffer + sizeof(struct ethhdr) + (iphdr->ihl * 4));

            // Check if destination is listen IP and port.
            if (iphdr->daddr == inet_addr(stuff->lIP))
            {
                // Forward packet.
                if (forwardPacket(IPPROTO_ICMP, buffer, sendsockfd, received, stuff) < 0)
                {
                    perror("forwardPacket");
                }
            }

            // Increment packet count.
            packetCount++;
        }
        // Check for IPIP protocol. This is replies we're receiving back from server we're forwarding to. Therefore, we have to process these and send back to client after stripping outer IP header.
        else if (iphdr->protocol == IPPROTO_IPIP)
        {
            // Initialize inner IP header.
            struct iphdr *Iiphdr = (struct iphdr *) (buffer + sizeof(struct ethhdr) + (iphdr->ihl * 4));

            // Check inner IP header's protocol.
            if (Iiphdr->protocol == IPPROTO_UDP)
            {
                // Reply back to client.
                if (replyToClient(IPPROTO_UDP, buffer, sendsockfd, received, stuff) < 0)
                {
                    perror("replyToClient");
                }

                // Increment sending packet count.
                sentPacketCount++;
            }
            else if (Iiphdr->protocol == IPPROTO_TCP)
            {
                // Reply back to client.
                if (replyToClient(IPPROTO_TCP, buffer, sendsockfd, received, stuff) < 0)
                {
                    perror("replyToClient");
                }

                // Increment sending packet count.
                sentPacketCount++;
            }
            else if (Iiphdr->protocol == IPPROTO_ICMP)
            {
                // Reply back to client.
                if (replyToClient(IPPROTO_ICMP, buffer, sendsockfd, received, stuff) < 0)
                {
                    perror("replyToClient");
                }

                // Increment sending packet count.
                sentPacketCount++;
            }
        }
    }

    // Close receiving and sending socket fds.
    close(sockfd);
    close(sendsockfd);

    // Print we're closing these (cleanup).
    fprintf(stdout, "Closing sockets.\n");

    // Exit thread.
    pthread_exit(NULL);
}

int main(int argc, char *argv[])
{
    // Check argument count.
    if (argc < 7)
    {
        fprintf(stderr, "Usage: %s <Listen IP> <Listen Port> <Destination IP> <Nat IP> <Nat Port> <Interface> [<Thread Count>]\n", argv[0]);

        exit(1);
    }

    // Initialize starting time.
    time_t startingTime = time(NULL);

    // Get PID for fanout group on AF_SOCKET.
    fanout_id = getpid() & 0xFFFF;

    // Get thread count based off CPU cores (this can be adjusted in the command line, though).
    uint8_t threads = get_nprocs_conf();

    // Check if threads argument is set.
    if (argc > 7)
    {
        threads = atoi(argv[7]);
    }

    // Initialize sending socket variable.
    int sendingSocket[threads];
 
    // Get destination MAC address which will be set to gateway's MAC address. I don't know if this is the best way to get the destination MAC address for the Ethernet header. But this was a recommended solution I found online.
    GetGatewayMAC();

    // Debug.
    fprintf(stdout, "Binding to %s:%u and redirecting to %s (%s:%u) with %" PRIu8 " threads and on interface %s.\n\n", argv[1], atoi(argv[2]), argv[3], argv[4], atoi(argv[5]), threads, argv[6]);

    // For loop for each thread we want to spawn.
    for (uint8_t i = 0; i < threads; i++)
    {
        // Setup sockaddr_ll struct for sending socket.
        struct sockaddr_ll a;

        // Set family to PF_PACKET.
        a.sll_family = PF_PACKET;

        // Set IF index to the interface's index specified in command line.
        a.sll_ifindex = if_nametoindex(argv[6]);

        // Set protocol to IP in network-byte-order (htons).
        a.sll_protocol = htons(ETH_P_IP);

        // Set MAC address length to 6 (ETH_ALEN).
        a.sll_halen = ETH_ALEN;

        // Create socket.
        sendingSocket[i] = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);

        // Check for errors!
        if (sendingSocket[i] < 0)
        {
            fprintf(stderr, "Socket() :: Error setting up sending socket #%d - %s\n", i, strerror(errno));
            perror("socket");

            exit(1);
        }

        // Bind socket.
        if (bind(sendingSocket[i], (struct sockaddr *)&a, sizeof(a)) < 0)
        {
            fprintf(stderr, "Bind() :: Error binding sending socket #%d - %s\n", i, strerror(errno));
            perror("bind");

            exit(1);
        }

        // Start putting data into structure we'll pass to each thread.
        struct stuff stuff;
        stuff.lIP = argv[1];
        stuff.lPort = atoi(argv[2]);
        stuff.dIP = argv[3];
        stuff.nIP = argv[4];
        stuff.dPort = atoi(argv[5]);
        stuff.interface = argv[6];
        stuff.sendingSocket = sendingSocket[i];

        // Debug.
        fprintf(stdout, "Starting thread #%" PRIu8 "\n", i);

        // Create new thread.
        pthread_t pid;

        // Check for errors on pthread_create.
        if (pthread_create(&pid, NULL, threadHndl, (void *)&stuff) != 0)
        {
            fprintf(stderr, "Error creating thread #%lu\n", pid);
        }
    }

    // Get interface's MAC address (source MAC address).
    struct ifreq ifr;

    // Copy interface name to struct.
    strcpy(ifr.ifr_name, argv[6]);

    // Send ioctl to first sending socket to get interface's source MAC address.
    if (ioctl(sendingSocket[0], SIOCGIFHWADDR, &ifr) != 0)
    {
        perror("ioctl");

        exit(1);
    }

    // Copy source MAC address to srcMac.
    memcpy(srcMac, ifr.ifr_addr.sa_data, ETH_ALEN);

    // Initiate signal function.
    signal(SIGINT, sigHndl);

    // Loop!
    while(cont)
    {
        // Allow the program to stay up until signaled to shutdown.
        sleep(1);
    }

    // Debug.
    fprintf(stdout, "Stopping...\n\n");

    // Allow cleanup of threads.
    sleep(2);

    // Get time again for stopping time.
    time_t stoppingTime = time(NULL);

    // Subtract startingTime from stoppingTime to get total time of program running.
    time_t timeE = stoppingTime - startingTime;

    // Print statistics.
    fprintf(stdout, "%d received packets and %d sent sockets in %jd seconds\n\n\n", packetCount, sentPacketCount, timeE);

    // Close program successfully.
    exit(0);
}