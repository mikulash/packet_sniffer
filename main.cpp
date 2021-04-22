#include <iostream>
#include <pcap/pcap.h>
#include <getopt.h>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <cstring>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

using namespace std;
using namespace std::chrono;
using namespace std;

/*zdroj hlavicek ethernet, ip a tcp https://www.tcpdump.org/pcap.html */

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14


/* IP header */
struct sniff_ip {
    u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
    u_char  ip_tos;                 /* type of service */
    u_short ip_len;                 /* total length */
    u_short ip_id;                  /* identification */
    u_short ip_off;                 /* fragment offset field */
    #define IP_RF 0x8000            /* reserved fragment flag */
    #define IP_DF 0x4000            /* don't fragment flag */
    #define IP_MF 0x2000            /* more fragments flag */
    #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
    u_char  ip_ttl;                 /* time to live */
    u_char  ip_p;                   /* protocol */
    u_short ip_sum;                 /* checksum */
    struct  in_addr ip_src,ip_dst;  /* source and dest address */
};


void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void printData(const u_char *payload, int len);
string now_rfc3339();
void print_hex_ascii_line(const u_char *payload, int len, int offset);


ether_header *eptr;
bool showTCP = false;
bool showUPD = false;
bool showICMP = false;
bool showARP = false;

int main(int argc, char **argv) {
    int opt;
    string port = " ip && port ";
    char portname[15];
    bool portselected = false;
    int numberOfPackets = 1;
    string rozhrani = "notset";
    bpf_u_int32 ip_raw;
    char subnet_mask[13];
    bool protokolNespecifikovan = true;
    pcap_if_t *alldevsp , *device;
    pcap_t *handle;
    int c;
    while (true)
    {
        static struct option long_options[] =
                {
                        {"", required_argument, nullptr, 'i'},
                        {"", required_argument, nullptr, 'p'},
                        {"tcp", no_argument,nullptr, 't'},
                        {"udp", no_argument,nullptr, 'u'},
                        {"icmp", no_argument,nullptr,'a'},
                        {"arp", no_argument,nullptr, 'b'},
                        {"",required_argument,nullptr, 'n'},
                        {"",0, nullptr,0}
                };
        int option_index = 0;
        c = getopt_long (argc, argv, "i:p:n:tun",
                         long_options, &option_index);
        if (c == -1)
            break;
        switch (c)
        {
            case 'i':
                //rozhrani
                rozhrani = optarg;
                break;
            case 'p':
                //port
                port.append(optarg);
                portselected = true;
                break;
            case 't':
                //ukaz TCP
                showTCP = true;
                protokolNespecifikovan = false;
                break;
            case 'd':
                //ukaz UDP
                showUPD = true;
                protokolNespecifikovan = false;
                break;
            case 'a':
                //ukaz ICMP
                showICMP = true;
                protokolNespecifikovan = false;
                break;
            case 'b':
                //ukaz ARP
                showARP = true;
                protokolNespecifikovan = false;
                break;
            case 'n':
                //ukaz pocet paketu
                numberOfPackets = atoi(optarg);
                break;
            default:
                exit(1);
        }
    }
    if (protokolNespecifikovan){
        showTCP = showICMP = showUPD = showARP = true;
    }
    strcpy(portname, port.c_str());

    char errbuf[PCAP_ERRBUF_SIZE];
    if( pcap_findalldevs( &alldevsp , errbuf) )
    {
        exit(1);
    }
    device = alldevsp;
    if (rozhrani == "notset"){
        while(device != nullptr){
            cout << device->name << std::endl;
            device = device->next;
        }
        exit(0);
    }

    handle = pcap_open_live(device->name, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr){
        cout << "handle == nullptr" << std::endl;
        exit(1);
    }
    if (pcap_datalink(handle) != DLT_EN10MB) {
        cout << "handle error" << std::endl;
        exit(1);
    }

    bpf_program fp;
    bpf_u_int32 mask;
    bpf_u_int32 net;
    if (pcap_lookupnet(device->name, &net, &mask, errbuf) == -1){ //vraci IPv4 adresu
        cout << "cannot get netmask" << std::endl;
        mask = 0;
        net = 0;
    }
    if (portselected){
        if( pcap_compile(handle, &fp, portname, 0, net) ==-1){
            cout << "compile error" << std::endl;
            return(1);
        }
        if (pcap_setfilter(handle, &fp) == -1){
            cout << "cannot install filter" << std::endl;
            return(1);
        }
    }

    pcap_loop(handle, numberOfPackets, got_packet, nullptr);

    //clean
    //pcap_freecode(&fp);
    pcap_close(handle);

    return 0;
}
//funkce pro zpracovani packetu
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){

    eptr = (ether_header*)packet;
    if (ntohs(eptr->ether_type) == ETHERTYPE_IP){

        const u_char *payload;
        const u_char *headerHexa;
        sockaddr_in source, dest;
        int ipHeaderLen;
        int sizePayload;
        int sizeHeader;
        sniff_ip *ip;
        ip = (sniff_ip*)(packet+SIZE_ETHERNET);
        auto *ipHeader = (iphdr*)(packet + SIZE_ETHERNET);

        ipHeaderLen = ipHeader->ihl * 4;

        memset(&source, 0, sizeof(source));
        memset(&dest, 0, sizeof(dest));
        source.sin_addr.s_addr = ipHeader->saddr;
        dest.sin_addr.s_addr = ipHeader->daddr;


        if (ipHeaderLen < 20){
            cout << "nevalidni IP hlavicka" << std::endl;
            return;
        }
        switch(ip->ip_p){
            case IPPROTO_TCP:
                if(showTCP){
                    auto *tcpheader = (tcphdr*)(packet + ipHeaderLen + SIZE_ETHERNET);
                    int tcpHeaderSize = tcpheader->doff * 4 + ipHeaderLen + SIZE_ETHERNET;

                    cout << now_rfc3339() <<" "<< inet_ntoa(source.sin_addr)<< " : " <<  ntohs(tcpheader->source);
                    cout << " > " << inet_ntoa(dest.sin_addr) << " : " << ntohs(tcpheader->dest) << ", length " << ntohs(ipHeader->tot_len) << " bytes" << std::endl;

                    headerHexa = (u_char*)(packet);
                    sizeHeader = ipHeaderLen + tcpheader->doff*4;

                    cout << "IP and TCP Headers:" << endl;
                    printData(headerHexa, sizeHeader);

                    payload = (u_char*)(packet + tcpHeaderSize);
                    sizePayload = ntohs(ipHeader->tot_len)+SIZE_ETHERNET - tcpHeaderSize;


                    if (tcpHeaderSize < 20){
                        cout << "nevalidni TCP hlavicka" << std::endl;
                        return;
                    }
                    int sizeAll = sizeHeader + sizePayload;
                    cout << "TCP Payload:" << endl;
                    printData(payload, sizePayload);

                    cout << std::endl;
                }
                break;
            case IPPROTO_UDP:
                if(showUPD){

                    auto *udpheader = (udphdr*)(packet + SIZE_ETHERNET + ipHeaderLen);
                    int udpHeaderSize = sizeof(udpheader) + SIZE_ETHERNET + ipHeaderLen ;

                    cout << now_rfc3339() <<" "<< inet_ntoa(source.sin_addr)<< " : " <<  ntohs(udpheader->source);
                    cout << " > " << inet_ntoa(dest.sin_addr) << " : " << ntohs(udpheader->dest) << ", length " << ntohs(ipHeader->tot_len) << " bytes" << std::endl;

                    headerHexa = (u_char*)(packet);
                    sizeHeader = ipHeaderLen + sizeof(udpheader);

                    cout << "IP and UDP Headers:" << endl;
                    printData(headerHexa, sizeHeader);

                    payload = (u_char*)(packet + udpHeaderSize);
                    sizePayload = ntohs(ipHeader->tot_len) - udpHeaderSize + SIZE_ETHERNET;

                    cout << "UDP Payload" << std::endl;
                    printData(payload, sizePayload);

                }
                break;
            case IPPROTO_ICMP:
                if (showICMP){

                    auto *icmpheader = (icmphdr*)(packet + SIZE_ETHERNET + ipHeaderLen);
                    int icmpHeaderSize = sizeof(icmpheader) + SIZE_ETHERNET + ipHeaderLen ;



                    payload = (u_char*)(packet + icmpHeaderSize);
                    sizePayload = ntohs(ipHeader->tot_len) - icmpHeaderSize;

                    cout << now_rfc3339() <<" "<< inet_ntoa(source.sin_addr);
                    cout << " > " << inet_ntoa(dest.sin_addr)  << ", length " << ntohs(ipHeader->tot_len) << " bytes" << std::endl;

                    cout << "IP and ICMP Header" << std::endl;
                    printData(payload, sizePayload);
                }
                break;
        }
    } else if (ntohs(eptr->ether_type) == ETHERTYPE_ARP){
        cout << "ARP" <<endl;


    } else{
        return;
    }
}
void printData(const u_char *payload, int len){
    const u_char *ch = payload;
    int offset = 0;
    int lineRest = len;
    int thisLineLength;
    if (len <= 0){return;}
    if (len < 16){
        print_hex_ascii_line(ch, len, offset);
    }
    while(true){
        thisLineLength = 16 % lineRest;
        print_hex_ascii_line(ch, thisLineLength, offset);
        lineRest = lineRest - thisLineLength;
        ch = ch + thisLineLength;
        offset += 16;
        if(lineRest <=16){
            print_hex_ascii_line(ch, lineRest, offset);
            break;
        }
    }
    cout << std::endl;
}

void print_hex_ascii_line(const u_char *payload, int len, int offset)
{
    int i;
    int gap;
    const u_char *ch;

    /* offset */
    //cout<<std::hex<< "0x" <<offset << ":";
    printf("0x%04x  ", offset);
    /* hex */
    ch = payload;
    for(i = 0; i < len; i++) {
        printf("%02x ", *ch);
        ch++;
        /* print extra space after 8th byte for visual aid */
        if (i == 7)
            printf(" ");
    }
    /* print space to handle line less than 8 bytes */
    if (len < 8)
        printf(" ");

    /* fill hex gap with spaces if not full line */
    if (len < 16) {
        gap = 16 - len;
        for (i = 0; i < gap; i++) {
            printf("   ");
        }
    }
    printf("   ");
    /* ascii (if printable) */
    ch = payload;
    for(i = 0; i < len; i++) {
        if (isprint(*ch))
            printf("%c", *ch);
        else
            printf(".");
        ch++;
    }
    cout << std::endl;
}

/*funkce pro cas ve formatu RFC3339 je odtud: https://stackoverflow.com/q/54325137 */
string now_rfc3339() {
    const auto now = system_clock::now();
    const auto millis = duration_cast<milliseconds>(now.time_since_epoch()).count() % 1000;
    const auto c_now = system_clock::to_time_t(now);

    stringstream ss;
    ss << put_time(gmtime(&c_now), "%FT%T") <<
       '.' << setfill('0') << setw(3) << millis << "+01:00";
    return ss.str();
}