Packet sniffer v C++

Přeložení lze provést příkazem make nebo make all. Pro úklid souborů lze použít make clean.

Projekt se spouští příkazem sudo ./ipk-sniffer a argumenty: [-i rozhraní | --interface rozhraní] {-p ­­port} {[--tcp|-t] [--udp|-u] [--arp] [--icmp] } {-n num}.
Je potřeba root oprávnění.

Program neumí vždy správně zpracovat velikost paketů s protokolem IPv6 a tiskne nuly navíc.

Možnou odlišností může být mnou implementované filtrování, kde filtrování probíhá až při zobrazování, podobně jako v programu wireshark.
Tedy například při argumentu --tcp jsou načítány všechny pakety, zpracováný a zobrazováný jsou ale jen tcp.

Do výstopního formátu jsem také ke každému packetu přidal název jeho protokolu a vypsané bajty rozdělil na hlavičky a payload.

