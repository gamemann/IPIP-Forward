#ifndef REDIRECT_HEADER

#include <stdio.h>
#include <inttypes.h>

#include "common.h"

#endif

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

unsigned char routerMac[ETH_ALEN];

void GetGatewayMAC()
{
    char cmd[] = "ip neigh | grep \"$(ip -4 route list 0/0|cut -d' ' -f3) \"|cut -d' ' -f5|tr '[a-f]' '[A-F]'";

    FILE *fp =  popen(cmd, "r");

    if (fp != NULL)
    {
        char line[18];

        if (fgets(line, sizeof(line), fp) != NULL)
        {
            sscanf(line, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &routerMac[0], &routerMac[1], &routerMac[2], &routerMac[3], &routerMac[4], &routerMac[5]);
        }

        pclose(fp);
    }

    printf("executed...\n");
}

void shiftChar(char *arr, int size, int dataLen)
{
    for (int16_t i = (dataLen - 1); i >= 0; i--)
    {
        memmove(arr + i + size, arr + i, 1);
    }

    for (int16_t i = 0; i < size; i++)
    {
        memcpy(arr + i, "0", 1);
    }
}

void removeChar(char *arr, int size, int dataLen)
{
    for (int16_t i = 0; i < dataLen; i++)
    {
        memmove(arr + i, arr + size + i, 1);
    }

    for (int16_t i = 0; i < size; i++)
    {
        memcpy(arr + size + dataLen - i, "0", 1);
    }
}