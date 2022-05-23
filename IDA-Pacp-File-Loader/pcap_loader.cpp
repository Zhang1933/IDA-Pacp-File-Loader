/*
*   Rewrite by Zhang1933
*/


#include"pcap_loader.h"

// 文件魔数判断
int accept_file(qstring* fileformatname, qstring* processor,
    linput_t* li, const char* filename) {
    uint32 magic;
    if (lread4bytes(li, &magic, 0) != 0// 小端
        || magic != PCAP_MAGIC) {
        return 0;
    }
    *fileformatname = "IDA Pcap Loader";
    return 1;
}

const char* pcap_types =
"struct timeval {\n"
"int tv_sec;\n"
"int tv_usec;\n"
"};\n"
"struct pcap_file_header {\n"
"int magic;\n"
"short version_major;\n"
"short version_minor;\n"
"int thiszone;\n"
"int sigfigs;\n"
"int snaplen;\n"
"int linktype;\n"
"};\n"
"struct pcap_pkthdr {\n"
"struct timeval ts;\n"
"int caplen;\n"
"int len;\n"
"};\n"

"struct ether_header {\n"
"char ether_dhost[6];\n"
"char ether_shost[6];\n"
"short ether_type;\n"
"};\n"

"struct iphdr {\n"
"char vhl;\n"
"char tos;\n"
"short tot_len;\n"
"short id;\n"
"short frag_off;\n"
"char ttl;\n"
"char protocol;\n"
"short check;\n"
"int saddr;\n"
"int daddr;\n"
"};\n"

"struct tcphdr {\n"
"short source;\n"
"short dest;\n"
"int seq;\n"
"int seq_ack;\n"
"char doff;\n"
"char flags;\n"
"short window;\n"
"short check;\n"
"short urg_ptr;\n"
"};\n"

"struct udphdr {\n"
"short source;\n"
"short dest;\n"
"short len;\n"
"short check;\n"
"};\n";

static tid_t pcap_hdr_struct;
static tid_t pkthdr_struct;
static tid_t ether_struct;
static tid_t ip_struct;
static tid_t tcp_struct;
static tid_t udp_struct;


// 加载一些已知数据结构到数据库
void add_types() {

    til_t* t = new_til("pcap.til", "pcap header types");// create empty type library
    parse_decls(t, pcap_types, msg, HTI_PAK1); //parse C declarations into library,HTI_PAK1请求 1 字节对齐的结构体
    sort_til(t);//required after til is modified

    /*The import_type function pulls the requested
    structure type from the specified type library into the database*/
    pcap_hdr_struct = import_type(t, -1, "pcap_file_header");
    pkthdr_struct = import_type(t, -1, "pcap_pkthdr");
    ether_struct = import_type(t, -1, "ether_header");
    ip_struct = import_type(t, -1, "iphdr");
    tcp_struct = import_type(t, -1, "tcphdr");
    udp_struct = import_type(t, -1, "udphdr");

    free_til(t);//free the temporary library ( Free memory allocated by til)
}

void load_file(linput_t* li, ushort neflags,
    const char* fileformatname) {
    ssize_t len;
    pcap_pkthdr pkt;
    uint32 pktnum = 0;

    add_types();//add structure templates to database

    //load the pcap file header from the file into the database
    file2base(li, 0, 0, sizeof(pcap_file_header), FILEREG_PATCHABLE);
    //try to add a new data segment to contain the file header bytes
    if (!add_segm(0, 0, sizeof(pcap_file_header), ".file_header", CLASS_DATA)) {
        loader_failure();
    }
    // 数据库中应用结构体
    create_struct(0, sizeof(pcap_file_header), pcap_hdr_struct);

    // 加载文件到数据库并分节：
    uint32 pos = sizeof(pcap_file_header);// file position tracker 
    while ((len = qlread(li, &pkt, sizeof(pkt))) == sizeof(pkt)) {// 读到内存来
        pktnum++;
        mem2base(&pkt, pos, pos + sizeof(pkt), pos);//transfer header to database
        pos += sizeof(pkt);

        //kernel remember correspondence of file offsets to linear addresses.
        file2base(li, pos, pos, pos + pkt.caplen, FILEREG_PATCHABLE);
        pos += pkt.caplen;

        // add segment
        qstring pktcnt_tmp = ".No.";
        pktcnt_tmp.cat_sprnt("%d", pktnum);
        if (!add_segm(0, pos - pkt.caplen - sizeof(pkt), pos, pktcnt_tmp.c_str(), CLASS_DATA)) {
            loader_failure();
        }
    }

    //retrieve a handle to the new segment
    segment_t* s = getseg(sizeof(pcap_file_header));
    //so that we can set 32 bit addressing mode on
    set_segm_addressing(s, 1);  //set 32 bit addressing

    //apply headers structs for each packet in the database
    for (uint32 ea = sizeof(pcap_file_header); ea < pos;) {
        uint32 pcap = ea;  //start of packet
        create_struct(pcap, sizeof(pcap_pkthdr), pkthdr_struct);

        uint32 eth = pcap + sizeof(pcap_pkthdr);// start of link layer
        create_struct(eth, sizeof(ether_header), ether_struct);
        // Test Ethernet type field
        uint16 etype = get_word(eth + ETHER_TYPE_OFFSET);

        etype = (etype >> 8) | (etype << 8);  //htons, big endian to little endian
        uint32 ip = eth + sizeof(ether_header);// get ip header

        if (etype == ETHER_TYPE_IP) {
            //Apply IP header struct
            create_struct(ip, sizeof(iphdr), ip_struct);
            //Test IP protocol
            uint8 proto = get_byte(ip + IPHDR_PROTOCOL_OFFSET);
            //compute IP header length
            uint32 iphl = (get_byte(ip) & 0xF) * 4;
            if (proto == IP_PROTO_TCP) {
                create_struct(ip + iphl, sizeof(tcphdr), tcp_struct);
            }
            else if (proto == IP_PROTO_UDP) {
                create_struct(ip + iphl, sizeof(udphdr), udp_struct);
            }
        }
        ea += get_dword(pcap + PCAP_PKTHDR_CAPLEN_OFFSET) + sizeof(pcap_pkthdr);
    }

    create_filename_cmt(); //tell IDA to create the Input file: File format:  comment for us.
}

//--------------------------------------------------------------------------
loader_t LDSC =
{
  IDP_INTERFACE_VERSION,
  LDRF_REQ_PROC, // Requires a processor to be set.
//
//      check input file format. if recognized, then return 1
//      and fill 'fileformatname'.
//      otherwise return 0
//
    accept_file,
    //
    //      load file into the database.
    //
     load_file,
     //
     //      create output file from the database.
     //      this function may be absent.
     //
       NULL,
       NULL,
       NULL,
};

