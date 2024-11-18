# DNS Monitor

**Author**: Varsányi Adam
**Login**: xvarsa01
**Date Created**: 18.11.2024  

## Description

The **DNS Monitor** program processes DNS protocol messages by reading network packets from either a live network interface (mode -i)or a existing PCAP file (-p). It provides detail informations about DNS queries and responses, supports logging of domain names, and translations of domain names to IP addresses. The program can be used in a verbose mode (-v) for more detailed output.

### Features:
- Captures DNS messages from a network interface or a PCAP file.
- Logs domain names to a specified file.
- Translates domain names into IP addresses and saves translations.
- Displays verbose output with detailed DNS message information.
- Supports multiple DNS record types, including A, AAAA, MX, NS, CNAME, and SOA.

### Limitations:
- The program works only on UDP layer and TCP is not supported.

## Example Usage
```bash
./dns-monitor -i eth0 -v
./dns-monitor -p file.pcpap
./dns-monitor -i eth0 -d domains.txt
./dns-monitor -i eth0 -t translations.txt
```
### Basic Usage:
Monitor DNS messages from the `eth0` interface in verbose mode:
```bash
./dns-monitor -i eth0 -v
```

## Used files:
- dns_monitor.c
- dns_monitor.h
- general_utils.c
- general_utils.h
- dns_utils.c
- dns_utils.h
- params.h
