# IPIP Forward Program

## Description
A simple IPIP forwarding program that supports UDP, TCP, and ICMP packets. This program uses raw AF_PACKET sockets. When a client sends a packet to the forwarding machine with the destination IP as the program's listen IP and the port is above 1024, it will create an IPIP packet by adding an outer IP header and send it to the destination IP along with performing NAT to the IPIP endpoint tunnel. When the program receives IPIP packets, it will send it back to the client.

## Notes
**Note** - As of right now, it only sends packets if the UDP/TCP port is above 1024. I know this is not convenient, but I plan to implement a feature that only excludes certain ports via a config file in a future program I plan to make. I am releasing the code to this program to simply show how the IPIP forwarding is done.

**Note** - This uses AF_PACKET sockets and the kernel does copy the packet to the user space. I plan to look into using [DPDK](https://www.dpdk.org/) at some point in the future which should result in better performance.

## Usage
Here's the program's usage:

```
./IPIPForward <Listen IP> <Listen Port> <Destination IP> <Nat IP> <Nat Port> <Interface> [<Thread Count>]
```

Here's an example:

```
./IPIPForward 10.50.0.3 27015 10.50.0.4 10.2.0.5 27015 ens18 4
```

## Compiling
I compiled this program using GCC 7.

Here's what I used to build the program:

```
gcc-7 -g IPIPForward.c -g common.c -o IPIPForward -lpthread
```

I also included warnings to ensure I wasn't missing anything there. However, this is the basic build command.

## Credits
* [Christian Deacon](https://www.linkedin.com/in/christian-deacon-902042186/) - Creator
* [Dreae](https://github.com/dreae) - For 'csum.h' file for calculating checksums, etc.