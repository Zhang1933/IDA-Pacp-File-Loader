/*
    Rewrite by Zhang1933
*/

#ifndef __PCAP_H
#define __PCAP_H

#include "../ldr/idaldr.h"// SDK中idaldr.h文件路径
#include <typeinf.hpp>


#ifdef _WIN64 
#include<winsock.h>
#elif __unix__
#include<sys/time.h>
#else
#error Unsupported platform compile on win64 or linux!
#endif


#define PCAP_MAGIC 0xA1B2C3D4

//from tcpdump.org's pcap.h
struct pcap_file_header {
    uint32 magic;
    uint16 version_major;
    uint16 version_minor;
    int32 thiszone;     /* gmt to local correction */
    uint32 sigfigs;    /* accuracy of timestamps */
    uint32 snaplen;    /* max length saved portion of each pkt */
    uint32 linktype;   /* data link type (LINKTYPE_*) */
};

#define PCAP_PKTHDR_CAPLEN_OFFSET 8

struct pcap_pkthdr {
    struct timeval ts;      /* time stamp */
    uint32 caplen;     /* length of portion present */
    uint32 len;        /* length this packet (off wire) */
};

#define ETHER_TYPE_IP 0x800
#define ETHER_TYPE_OFFSET 12

struct ether_header {
    uint8 ether_dhost[6];
    uint8 ether_shost[6];
    uint16 ether_type;
};


#define IP_PROTO_TCP 6
#define IP_PROTO_UDP 17

#define IPHDR_PROTOCOL_OFFSET 9

struct iphdr {
    uint8 vhl;
    uint8 tos;
    uint16 tot_len;
    uint16 id;
    uint16 frag_off;
    uint8 ttl;
    uint8 protocol;
    uint16 check;
    uint32 saddr;
    uint32 daddr;
};

struct tcphdr {
    uint16 source;
    uint16 dest;
    uint32 seq;
    uint32 seq_ack;
    uint8 doff;
    uint8 flags;
    uint16 window;
    uint16 check;
    uint16 urg_ptr;
};

struct udphdr {
    uint16 source;
    uint16 dest;
    uint16 len;
    uint16 check;
};


#endif

