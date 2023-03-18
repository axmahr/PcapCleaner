# PcapCleaner
[pcapcleaner.py](pcapcleaner.py) filters background traffic from of a given pcap/pcapng file and returns a filtered pcap file. Background traffic includes especially communication with certain domains (e.g. Windows update server), traffic relating to connections with these domains like OCSP and ICMP packets, TLS connections with matching JA3/JA3S fingerprints, periodic TCP connections, traffic of certain protocols and more. For a detailed list of what is getting filtered, take a look at the [corresponding section](#what-is-getting-filtered-in-detail) below .

You have to pass a file of domains (like [domains.txt](domains.txt)) and/or a file with JA3 and JA3S fingerprints (like [ja3_ja3s_hashes.txt](ja3_ja3s_hashes.txt)) to PcapCleaner via the option `-t/--targets` and/or `-j/--ja3`.
The given files [domains.txt](domains.txt) and [ja3_ja3s_hashes.txt](ja3_ja3s_hashes.txt) include domains and fingerprints of an extensive amount of background traffic that was captured in advance on Windows 10 (version 20H2/21H1/21H2) and Ubuntu (version 21.04/21.10) machines.

To create your own file with domains and fingerprints or complement the given files you can run [extract_features.py](feature_extraction/extract_features.py) in the folder [feature_extraction](feature_extraction). This script will output all domains and JA3/JA3S fingerprints in the format needed for PcapCleaner.

Since the tool needs to iterate over the whole capture file multiple times (and it's written in Python) it might take 1 or 2 minutes to run for big files.

To test whether PcapCleaner works for you, run:
```
python3 pcapcleaner.py -f pcaps/win_sample.pcap -t domains.txt -j ja3_ja3s_hashes.txt --filter-periodicity
```

# Requirements
PcapCleaner needs to run on Linux. Python 3.7+ and Scapy is required. 
```
pip install scapy
```

# Usage
```
python3 pcapcleaner.py -f <input-pcap> [options]
```
possible options:
 - `-t/--targets <domains-file>` file containing the domain names to be filtered
 - `-j/--ja3 <fingerprints-file>`: file containing JA3 and JA3S fingerprints of the TLS connections to be filtered
 - `--filter-periodicity`: additionally filter periodic TCP connections (this includes periodicity whithin a TCP connection and between TCP connections with the same domain) and filter incomplete TCP connections
 - `--export-rule`: return a file containing a Wireshark display filter for coloring the filtered packets in the original capture file via `View->Coloring Rules...->Import`. The file might not be created when the given capture file is too large.

 `-t/--targets` and/or `-j/--ja3` must be set.

# What is getting filtered in detail?
As already mentioned, this tool primarily filters connections with specified domains or TLS fingerprints. The correct Domain-IP mapping is produced by parsing DNS responses, HTTP Host and SNI values. In addition the following traffic is filtered:
- OCSP traffic which refers to background traffic (detection through the serial number of the checked certificate)
- ICMP/ICMPv6 packets which refer to background traffic or to IP addresses belonging to background traffic
- ICMPv6 Neighbor Solicitation/Advertisement
- packets without IP layer
- packets which have a multicast address as destination address
- DHCP, DHCPv6 NBNS, NTP packets
- DNS query/response belonging to background traffic, DNS PTR type

When the option `--filter-periodicity` is selected, PcapCleaner also filters
- TCP connections with repeating inter-packet times greater than 5 seconds
- TCP connections with the same domain which are established periodically
- incomplete TCP connections (incomplete/aborted 3-way handshake or closed immediately after handshake)
- DNS traffic that belongs to periodic connections 


## Why JA3?
There are domains that communicate both through foreground and background traffic. `bing.com`, e.g., can be requested actively by users but is also used to call up the latest news for the Windows Live Tiles in the background. In order to be able to distinguish whether a given connection to such a domain is background traffic or not, JA3 and JA3S fingerprints can be used because different clients and servers are used. You can find out more about JA3 in the corresponding [Github repository](https://github.com/salesforce/ja3).
