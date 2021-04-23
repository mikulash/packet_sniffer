#include <iostream>
#include <unistd.h>
#include <pcap/pcap.h>
#include <getopt.h>
using namespace std;

void processPacket(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

int main(int argc, char **argv) {
    int opt;
    char *port;
    bool showTCP = false;
    bool showUPD = false;
    bool showICMP = false;
    bool showARP = false;
    int numberOfPackets = 10;
    string rozhrani = "notset";
    bpf_u_int32 ip_raw;
    char subnet_mask[13];
    pcap_if_t *alldevsp , *device;
    pcap_t *handle;
    int c;
    while (true)
    {
        static struct option long_options[] =
                {
                        {"",     required_argument,       nullptr, 'i'},
                        {"",  required_argument,       nullptr, 'p'},
                        {"tcp",  no_argument, nullptr, 't'},
                        {"udp",  no_argument, nullptr, 'u'},
                        {"icmp",    no_argument, nullptr,'a'},
                        {"arp",    no_argument, nullptr, 'b'},
                        {"",    required_argument, nullptr, 'n'},
                        {"", 0, nullptr, 0}
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
                port = optarg;
                break;
            case 't':
                //ukaz TCP
                showTCP = true;
                break;
            case 'd':
                //ukaz UDP
                showUPD = true;
                break;
            case 'a':
                //ukaz ICMP
                showICMP = true;
                break;
            case 'b':
                //ukaz ARP
                showARP = true;
                break;
            case 'n':
                //ukaz pocet paketu
                numberOfPackets = atoi(optarg);
                break;
            default:
                abort ();
        }
    }



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
    char filterExp[] = "port 403";
    bpf_u_int32 mask;
    bpf_u_int32 net;
    if (pcap_lookupnet(device->name, &net, &mask, errbuf) == -1){ //vraci IPv4 adresu
        cout << "cannot get netmask" << std::endl;
        mask = 0;
        net = 0;
    }

    if( pcap_compile(handle, &fp, filterExp, 0, net) ==-1){
        cout << "compile error" << std::endl;
        exit(1);
    }
    if (pcap_setfilter(handle, &fp) == -1){
        cout << "cannot install filter" << std::endl;
        exit(1);
    }

    const u_char *packet;
    pcap_pkthdr header;
    cout << "jsem tu" << std::endl;
    cout << device->name << std::endl;
    //packet = pcap_next(handle, &header);
    pcap_loop(handle, numberOfPackets, processPacket, nullptr);
    cout << header.len << std::endl;
    pcap_close(handle);
    cout << "proslo zatim ok" << std::endl;

    return 0;
}
void processPacket(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    cout << "jsem tu" << std::endl;
}