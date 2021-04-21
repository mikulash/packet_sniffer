#include <iostream>
#include <unistd.h>
#include <pcap/pcap.h>
using namespace std;

int main(int argc, char **argv) {
    std::cout << "Hello, World!" << std::endl;
    int opt;
    int port = 23;
    bool showTCP = true;
    bool showUPD = true;
    bool showICMP = true;
    bool showArp = true;
    int numberOfPackets = 10;
    string rozhrani = "eth0";

    pcap_if_t *alldevsp , *device;
    pcap_t *handle; //Handle of the device that shall be sniffed

    char errbuf[100] , *devname , devs[100][100];
    int count = 1 , n;

    if( pcap_findalldevs( &alldevsp , errbuf) )
    {
        exit(1);
    }
    for(device = alldevsp ; device != nullptr ; device = device->next)
    {
        cout << device->name << std::endl;
    }


    //cout << device->name << std::endl;
    /*
     * parse arguments
    while ((opt = getopt (argc, argv, "aptun")) != -1)
    {
        switch (opt)
        {
            case 'i':
                rozhrani = optarg;
                break;
            case 'p':

                break;
            case 't':
            case 'tcp':

                break;
            case 'u':
            case 'udp':

                break;
            case 'icmp':

                break;
            case 'arp':
                break;
            case 'n':
                numberOfPackets = optarg;
                break;
        }
    }*/

    return 0;
}
