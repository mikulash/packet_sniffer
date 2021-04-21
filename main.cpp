#include <iostream>
#include <unistd.h>
#include <pcap/pcap.h>
#include <getopt.h>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <cstring>

using namespace std;
using namespace std::chrono;
using namespace std;

/*zdroj hlavicek ethernet, ip a tcp https://www.tcpdump.org/pcap.html */

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
    u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
    u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
    u_short ether_type;                     /* IP? ARP? RARP? etc */
};

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
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
    u_short th_sport;               /* source port */
    u_short th_dport;               /* destination port */
    tcp_seq th_seq;                 /* sequence number */
    tcp_seq th_ack;                 /* acknowledgement number */
    u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
    u_char  th_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;                 /* window */
    u_short th_sum;                 /* checksum */
    u_short th_urp;                 /* urgent pointer */
};
struct sniff_udp{
    u_short th_sport;               /* source port */
    u_short th_dport;               /* destination port */
    u_short length;
    u_short checksum;
};
struct sniff_icmp{
    u_short type;               /* source port */
    u_short code;               /* destination port */
    unsigned short checksum;
};

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void printPayload(const u_char *payload, int len);
string now_rfc3339();
void print_hex_ascii_line(const u_char *payload, int len, int offset);



int main(int argc, char **argv) {
    int opt;
    string port = "port ";
    char portname[15];
    bool showTCP = false;
    bool showUPD = false;
    bool showICMP = false;
    bool showARP = false;
    int numberOfPackets = 1;
    string rozhrani = "notset";
    bpf_u_int32 ip_raw;
    char subnet_mask[13];
    bool protokolspecifikovan = false;
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
                break;
            case 't':
                //ukaz TCP
                showTCP = true;
                protokolspecifikovan = true;
                break;
            case 'd':
                //ukaz UDP
                showUPD = true;
                protokolspecifikovan = true;
                break;
            case 'a':
                //ukaz ICMP
                showICMP = true;
                protokolspecifikovan = true;
                break;
            case 'b':
                //ukaz ARP
                showARP = true;
                protokolspecifikovan = true;
                break;
            case 'n':
                //ukaz pocet paketu
                numberOfPackets = atoi(optarg);
                break;
            default:
                abort ();
        }
    }

    strcpy(portname, port.c_str());

    char errbuf[PCAP_ERRBUF_SIZE] , *devname , devs[100][100];
    int count = 1 , n;
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

    int compileError;
    bpf_program fp;
    bpf_u_int32 mask;
    bpf_u_int32 net;
    if (pcap_lookupnet(device->name, &net, &mask, errbuf) == -1){ //vraci IPv4 adresu
        cout << "cannot get netmask" << std::endl;
        mask = 0;
        net = 0;
    }

    if( pcap_compile(handle, &fp, portname, 0, net) ==-1){
        cout << "compile error" << std::endl;
        exit(1);
    }
    if (pcap_setfilter(handle, &fp) == -1){
        cout << "cannot install filter" << std::endl;
        exit(1);
    }

    const u_char *packet;
    pcap_pkthdr header;

    pcap_loop(handle, numberOfPackets, got_packet, nullptr);

    //clean
    pcap_freecode(&fp);
    pcap_close(handle);

    return 0;
}
//funkce pro zpracovani packetu
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    const u_char *payload;
    int sizeIP;
    int sizeTCP;
    int sizePayload;
    sniff_ethernet *ethernet;
    sniff_ip *ip;
    sniff_tcp *tcp;
    ethernet = (sniff_ethernet*)(packet);
    ip = (sniff_ip*)(packet+SIZE_ETHERNET);
    sizeIP = IP_HL(ip)*4;
    if (sizeIP < 20){
        cout << "nevalidni IP hlavicka" << std::endl;
    }
    switch(ip->ip_p){
        case IPPROTO_TCP:
            tcp = (sniff_tcp*)(packet + SIZE_ETHERNET + sizeIP);
            sizeTCP = TH_OFF(tcp)*4;
            if (sizeTCP < 20){
                cout << "nevalidni TCP hlavicka" << std::endl;
            }
            cout << std::endl;
            payload = (u_char*)(packet + SIZE_ETHERNET + sizeIP + sizeTCP);
            sizePayload = ntohs(ip->ip_len) - (sizeIP + sizeTCP);
            cout << now_rfc3339() <<" "<< inet_ntoa(ip->ip_src)<< " : " << ntohs(tcp->th_sport);
            cout << " > "<<inet_ntoa(ip->ip_dst) << " : " << ntohs(tcp->th_dport)<<", "<< sizePayload<< " bytes" << std::endl;
            printPayload(payload, sizePayload);
            break;
        case IPPROTO_UDP:
            cout << "UDP" << std::endl;
        case IPPROTO_ICMP:
            cout << "ICMP" << std::endl;
    }
}
void printPayload(const u_char *payload, int len){
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
    cout << payload << std::endl;
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