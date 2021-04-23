.PHONY: all clean

all:
	g++ main.cpp -o ipk-sniffer -lpcap

clean:
	-rm -f ipk-sniffer
