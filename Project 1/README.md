# 📌 Port Scan Detection Engine

![Python](https://img.shields.io/badge/python-3.x-green.svg)

## 📝 Overview
This project is a high-performance network forensics tool designed to detect and classify various Nmap port scanning techniques. By parsing raw packet data from `.pcap` files using the `dpkt` library, the tool identifies malicious scanning patterns and reports the number of unique ports targeted for each specific scan type.

- Parse complex PCAP files captured via Wireshark/tcpdump.
- Differentiate between stealth (Half-Open) and full-connection (TCP Connect) scans.
- Identify malformed packet scans (Null and XMAS).
- Quantify unique port targets to measure the scope of reconnaissance.

## ⚙️ Methodology / Approach
The engine follows a three-stage analysis process:
1.  **De-encapsulation:** Using `dpkt` to strip Ethernet and IP headers to reach the Transport Layer (TCP/UDP).
2.  **Signature Matching:** Analyzing TCP Flag combinations against known Nmap signatures.
    - **Null Scan:** Checks for a `0x00` flag set.
    - **XMAS Scan:** Checks for the "Christmas Tree" pattern (FIN, PSH, and URG flags).
3.  **State Tracking:** Monitoring the handshake sequence to distinguish between a completed `Connect()` scan and a stealthy `SYN` (Half-Open) scan.
4.  **Deduplication:** Utilizing Python sets to ensure that retransmitted packets or multi-step handshakes are counted as a single unique port scan per source IP.

## 🛠️ Tools & Technologies
- **Python 3.x:** Primary development language.
- **DPKT Library:** Used for fast, low-level packet parsing.
- **Wireshark:** Used to capture and validate test traffic.
- **Nmap:** Used to generate the various scan types for the test dataset.

## 💻 Implementation / Steps
The script is designed to be executed via the CLI and follows strict output requirements for automated grading or SIEM integration.

### Usage
```bash
python3 <chargerID>.py -i <filename.pcap>
