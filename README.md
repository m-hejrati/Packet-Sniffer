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

for logging, we use spdlog library, download it from git:
```bash
git clone https://github.com/gabime/spdlog.git
```

for compiling C++ program we should add -lpcap and -ljson-c and directory name of spdlog library:
```bash
g++ sniffer.cpp -o sniffer.out -lpcap -ljson-c -I "spdlog/include"
````

and it needs to run with sudo:
```bash
sudo ./sniffer.out
````