#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

#ifndef REDIRECT_HEADER
#include <string.h>
#endif

// Max packet length for buffer in bytes.
#define MAX_PCKT_LENGTH 65535

// Variable for signal.
static int cont = 1;

// Packet statistics.
static int packetCount = 0;
static int sentPacketCount = 0;

// Both source and destination MAC addresses for Ethernet header.
extern unsigned char routerMac[ETH_ALEN];
static unsigned char srcMac[ETH_ALEN];

// Fanout ID for AF_PACKET socket.
static int fanout_id;

// Common functions.
void GetGatewayMAC();
void shiftChar(char *arr, int size, int dataLen);
void removeChar(char *arr, int size, int dataLen);