#include <iostream>
#include <pcap/pcap.h>
#include <getopt.h>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>

using namespace std;
using namespace std::chrono;

/* ethernet headers are always 14 bytes */
#define SIZE_ETHERNET 14

void processPacket(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void printData(const u_char *payload, int len);
/*funkce pro cas ve formatu RFC3339 je z: https://stackoverflow.com/q/54325137 */
string now_rfc3339();
/*funkce pro vystupni format tisku prevzata z https://www.tcpdump.org/pcap.html */
void print_hex_ascii_line(const u_char *payload, int len, int offset);


ether_header *eptr;
//booleany for display filter
bool showTCP = false;
bool showUPD = false;
bool showICMP = false;
bool showARP = false;

int main(int argc, char **argv) {

    string port = "port ";
    char portname[15];
    bool portselected = false;
    int numberOfPackets = 1;
    string deviceName = "notset";
    bool protocolNotSpecified = true;
    pcap_if_t *alldevsp , *device;
    pcap_t *handle;
    int c;
    //parsing arguments
    while (true)
    {
        static struct option long_options[] =
                {
                        {"interface", required_argument, nullptr, 'i'},
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
                deviceName = optarg;
                break;
            case 'p':
                // get port
                port.append(optarg);
                portselected = true;
                break;
            case 't':
                showTCP = true;
                protocolNotSpecified = false;
                break;
            case 'u':
                showUPD = true;
                protocolNotSpecified = false;
                break;
            case 'a':
                showICMP = true;
                protocolNotSpecified = false;
                break;
            case 'b':
                showARP = true;
                protocolNotSpecified = false;
                break;
            case 'n':
                numberOfPackets = atoi(optarg);
                break;
            case '?':
                if (optopt == 'i'){
                    cout << "i without param" <<endl;
                    break;
                } else exit(1);
            default:
                cout << "not valid argument" << endl;
                exit (1);
            ;
        }
    }
    if (protocolNotSpecified){
        showTCP = showICMP = showUPD = showARP = true;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    if( pcap_findalldevs( &alldevsp , errbuf) ) //find active devices
    {
        exit(1);
    }
    device = alldevsp;
    if (deviceName == "notset"){  // if no active device was found
        while(device != nullptr){
            cout << device->name << std::endl;
            device = device->next;
        }
        exit(0);
    }

    handle = pcap_open_live(device->name, BUFSIZ, 1, 1000, errbuf); //opening ""sniffing session"
    if (handle == nullptr){
        cout << "handle == nullptr" << std::endl;
        exit(1);
    }
    if (pcap_datalink(handle) != DLT_EN10MB) { //check presence of ethernet header
        cout << "handle error" << std::endl;
        exit(1);
    }

    bpf_program fp;
    bpf_u_int32 mask;
    bpf_u_int32 net;
    if (pcap_lookupnet(device->name, &net, &mask, errbuf) == -1){ //returns ipv4 network number and network mask
        cout << "cannot get netmask" << std::endl;
        mask = 0;
        net = 0;
    }
    if (portselected){
        if( pcap_compile(handle, &fp, portname, 0, net) ==-1){ //compile filter
            cout << "compile error" << std::endl;
            return(1);
        }
        if (pcap_setfilter(handle, &fp) == -1){
            cout << "cannot install filter" << std::endl;
            return(1);
        }
    }

    pcap_loop(handle, numberOfPackets, processPacket, nullptr); //calls processPacket function for every packet found

    //clean
    //pcap_freecode(&fp);
    pcap_close(handle);

    return 0;
}

//callback function for pcap_loop
void processPacket(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){

    eptr = (ether_header*)packet;
    if (ntohs(eptr->ether_type) == ETHERTYPE_IP){ //if device has ip header

        const u_char *payload;
        const u_char *headerHexa;
        sockaddr_in source, dest;
        int ipHeaderLen;
        int sizePayload;
        int sizeHeader;
        auto *ipHeader = (iphdr*)(packet + SIZE_ETHERNET);

        ipHeaderLen = ipHeader->ihl * 4;
        if (ipHeaderLen < 20){
            cout <<ipHeaderLen << endl;
            cout << "nevalidni IP hlavicka" << std::endl;
            return ;
        }
        //gets source and destination addresses
        source.sin_addr.s_addr = ipHeader->saddr;
        dest.sin_addr.s_addr = ipHeader->daddr;

        switch(ipHeader->protocol){
            //numbers according to protocol numbers, viz https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
            case 1: //if protocol is ICMP
                if (showICMP){ //if we want to display packets with protocol ICMP

                    auto *icmpheader = (icmphdr*)(packet + SIZE_ETHERNET + ipHeaderLen);
                    int icmpHeaderSize = sizeof(icmpheader) + SIZE_ETHERNET + ipHeaderLen;

                    //sets offset for payload
                    payload = (u_char*)(packet + icmpHeaderSize);
                    sizePayload = ntohs(ipHeader->tot_len) - icmpHeaderSize;
                    cout << "ICMPv4:" << endl;
                    //print time and data about packet and headervalue of packet
                    cout << now_rfc3339() <<" "<< inet_ntoa(source.sin_addr);
                    cout << " > " << inet_ntoa(dest.sin_addr)  << ", length " << ntohs(ipHeader->tot_len) << " bytes" << std::endl;
                    printData(payload, sizePayload);
                }
                break;
            case 6:
                //if we want to display packets with protocol TCP
                if(showTCP){
                    auto *tcpheader = (tcphdr*)(packet + ipHeaderLen + SIZE_ETHERNET);
                    int tcpHeaderSize = tcpheader->doff * 4 + ipHeaderLen + SIZE_ETHERNET;

                    cout << now_rfc3339() <<" "<< inet_ntoa(source.sin_addr)<< " : " <<  ntohs(tcpheader->source);
                    cout << " > " << inet_ntoa(dest.sin_addr) << " : " << ntohs(tcpheader->dest) << ", length " << ntohs(ipHeader->tot_len) << " bytes" << std::endl;
                    //sets offset for headers
                    headerHexa = (u_char*)(packet);
                    sizeHeader = ipHeaderLen + tcpheader->doff*4+SIZE_ETHERNET;

                    cout << "IP and TCP Headers:" << endl;
                    if (sizeHeader > 0){
                        printData(headerHexa, sizeHeader);
                    }

                    //sets offset for payload
                    payload = (u_char*)(packet + tcpHeaderSize);
                    sizePayload = ntohs(ipHeader->tot_len)+SIZE_ETHERNET - tcpHeaderSize;

                    if (tcpHeaderSize < 20){
                        cout << "invalid TCP header" << std::endl;
                        return;
                    }

                    if(sizePayload > 0){
                        cout << "TCP Payload" << std::endl;
                        printData(payload, sizePayload);
                    }

                    cout << std::endl;
                }
                break;
            case 17:
                //if we want to display packets with protocol UDP
                if(showUPD) {

                    auto *udpheader = (udphdr *) (packet + SIZE_ETHERNET + ipHeaderLen);
                    int udpHeaderSize = sizeof(udpheader) + SIZE_ETHERNET + ipHeaderLen;

                    cout << now_rfc3339() << " " << inet_ntoa(source.sin_addr) << " : " << ntohs(udpheader->source);
                    cout << " > " << inet_ntoa(dest.sin_addr) << " : " << ntohs(udpheader->dest) << ", length "
                         << ntohs(ipHeader->tot_len) << " bytes" << std::endl;

                    //sets offset for headers
                    headerHexa = (u_char *) (packet);
                    sizeHeader = ipHeaderLen + sizeof(udpheader) + SIZE_ETHERNET;

                    cout << "IP and UDP Headers:" << endl;
                    if (sizeHeader > 0){
                        printData(headerHexa, sizeHeader);
                    }

                    //sets offset for payload
                    payload = (u_char *) (packet + udpHeaderSize);
                    sizePayload = ntohs(ipHeader->tot_len) - udpHeaderSize + SIZE_ETHERNET;


                    if(sizePayload > 0){
                        cout << "UDP Payload" << std::endl;
                        printData(payload, sizePayload);
                    }
                }
                    break;
            default:
                //cout<< "unsupported protocol " << ntohs(ipHeader->protocol) << endl;
                break;
        }

    }else if(ntohs(eptr->ether_type) == ETHERTYPE_IPV6){
        const u_char *payload;
        const u_char *headerHexa;
        sockaddr_in6 source, dest;
        int ipHeaderLen;
        int sizePayload;
        int sizeHeader;
        auto *ipHeader = (ip6_hdr*)(packet + SIZE_ETHERNET);

        ipHeaderLen = 40;

        //gets source and destination addresses
        source.sin6_addr = ipHeader->ip6_src;
        dest.sin6_addr = ipHeader->ip6_dst;

        char srcstring[INET6_ADDRSTRLEN];
        char dststring[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &source.sin6_addr, srcstring, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &dest.sin6_addr, dststring, INET6_ADDRSTRLEN);


        uint8_t protocol = ipHeader->ip6_ctlun.ip6_un1.ip6_un1_nxt;
        if (protocol == 0){
            ipHeaderLen = 48;
            protocol = *(uint8_t*)(packet + 40);
        }

        sizePayload = ipHeader->ip6_ctlun.ip6_un1.ip6_un1_plen;

        switch(protocol){
            //numbers according to protocol numbers, viz https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
            case 58: //if protocol is ICMPv6
                if (showICMP){ //if we want to display packets with protocol ICMP

                    auto *icmpheader = (icmp6_hdr*)(packet + SIZE_ETHERNET + ipHeaderLen);
                    int icmpHeaderSize = sizeof(icmpheader) + SIZE_ETHERNET + ipHeaderLen;

                    //sets offset for payload
                    payload = (u_char*)(packet + icmpHeaderSize);

                    //print time and data about packet and headervalue of packet
                    cout << "ICMPv6:" << endl;
                    cout << now_rfc3339() <<" "<< srcstring;
                    cout << " > " << dststring  << ", length " << sizePayload+ipHeaderLen+SIZE_ETHERNET << " bytes" << std::endl;
                    printData(payload, sizePayload);
                }
                break;
            case 6:
                //if we want to display packets with protocol TCP
                if(showTCP){
                    auto *tcpheader = (tcphdr*)(packet + ipHeaderLen + SIZE_ETHERNET);
                    int tcpHeaderSize = tcpheader->doff * 4 + ipHeaderLen + SIZE_ETHERNET;

                    cout << now_rfc3339() <<" "<< srcstring<< " : " <<  ntohs(tcpheader->source);
                    cout << " > " << dststring << " : " << ntohs(tcpheader->dest) << ", length " << sizePayload+ipHeaderLen+SIZE_ETHERNET << " bytes" << std::endl;
                    //sets offset for headers
                    headerHexa = (u_char*)(packet);
                    sizeHeader = ipHeaderLen + tcpheader->doff*4+SIZE_ETHERNET;

                    cout << "IP and TCP Headers:" << endl;
                    if (sizeHeader > 0){
                        printData(headerHexa, sizeHeader);
                    }

                    //sets offset for payload
                    payload = (u_char*)(packet + tcpHeaderSize);

                    if (tcpHeaderSize < 20){
                        cout << "invalid TCP header" << std::endl;
                        return;
                    }

                    if(sizePayload > 0){
                        cout << "TCP Payload" << std::endl;
                        printData(payload, sizePayload);
                    }

                    cout << std::endl;
                }
                break;
            case 17:
                //if we want to display packets with protocol UDP
                if(showUPD) {

                    auto *udpheader = (udphdr *) (packet + SIZE_ETHERNET + ipHeaderLen);
                    int udpHeaderSize = sizeof(udpheader) + SIZE_ETHERNET + ipHeaderLen;

                    cout << now_rfc3339() << " " << srcstring << " : " << ntohs(udpheader->source);
                    cout << " > " << dststring << " : " << ntohs(udpheader->dest) << ", length "
                         << sizePayload+ipHeaderLen+SIZE_ETHERNET << " bytes" << std::endl;

                    //sets offset for headers
                    headerHexa = (u_char *) (packet);
                    sizeHeader = ipHeaderLen + sizeof(udpheader) + SIZE_ETHERNET;

                    cout << "IP and UDP Headers:" << endl;
                    if (sizeHeader > 0){
                        printData(headerHexa, sizeHeader);
                    }

                    //sets offset for payload
                    payload = (u_char *) (packet + udpHeaderSize);

                    if(sizePayload > 0){
                        cout << "UDP Payload" << std::endl;
                        printData(payload, sizePayload);
                    }
                }
                break;
            default:
                //cout<< "unsupported protocol " << ntohs(protocol) << endl;
                break;
        }

    } else if (ntohs(eptr->ether_type) == ETHERTYPE_ARP){ //if device has ARP header
        if (showARP){
            cout << now_rfc3339() << " ";

            const u_char *ch = packet + 6; //source address offset is always 6 bits
            int i;
            for(i = 0; i < 6; i++) {
                if(i != 5){
                    printf("%02x:", *ch);
                } else
                    printf("%02x", *ch);
                ch++;
            }
            cout << endl;
            cout << "ARP" <<endl;
            if (header->len > 0){
                printData(packet, header->len);
            }
        }
    } else{
        //cout<< "unsupported ether type" << endl;
        return;
    }
}
void printData(const u_char *payload, int len){
    const u_char *addr = payload;
    int offset = 0;
    int lineRest = len;
    int thisLineLength;
    if (len < 16){
        //if line shorter, dont loop
        print_hex_ascii_line(addr, len, offset);
    }else{
        while(true){
            //loop until all printed
            thisLineLength = 16 % lineRest;
            print_hex_ascii_line(addr, thisLineLength, offset);
            lineRest = lineRest - thisLineLength;
            addr = addr + thisLineLength;
            offset += 16;
            if(lineRest <=16){
                print_hex_ascii_line(addr, lineRest, offset);
                break;
            }
        }
    }

    cout << std::endl;
}

/*funkce pro vystupni format tisku prevzata z https://www.tcpdump.org/pcap.html
 * Autor: Tim Carstens*/
void print_hex_ascii_line(const u_char *payload, int len, int offset)
{
    int i;
    int gap;
    const u_char *ch;

    /* offset */
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

/*funkce pro cas ve formatu RFC3339 je z: https://stackoverflow.com/q/54325137*/
string now_rfc3339() {
    const auto now = system_clock::now();
    const auto millis = duration_cast<milliseconds>(now.time_since_epoch()).count() % 1000;
    const auto c_now = system_clock::to_time_t(now);

    stringstream ss;
    ss << put_time(gmtime(&c_now), "%FT%T") <<
       '.' << setfill('0') << setw(3) << millis << "+01:00"; //timezone hardcoded
    return ss.str();
}