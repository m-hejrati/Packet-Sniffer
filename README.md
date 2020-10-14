# Packet Sniffer
Packet sniffer with C++ language and pcap

## Installation

we use libpcaq library in this project, for installing it you can write this command:
```bash
sudo apt-get install libpcap-dev
```

config files written in json format, we use json-c library to parse them:
```bash
sudo apt install libjson-c-dev
```

for compiling C++ program we should add -lpcap and -ljson-c:
```bash
g++ sniffer.cpp -o sniffer.out -lpcap -ljson-c
````
and it needs to run with sudo:
```bash
sudo ./sniffer.out
````