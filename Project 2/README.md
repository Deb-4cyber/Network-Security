# 📌 Port Knocking Sequence Detector (HIDS Engine)

![Python](https://img.shields.io/badge/python-3.x-green.svg)

## 📝 Overview
This project demonstrates the implementation and forensic detection of **Port Knocking**, a defense-in-depth technique used to stealthily open firewall ports. The goal was to build a specialized **Host-based Intrusion Detection System (HIDS)** that automates the analysis of network traffic to identify hidden connection sequences and validate them against system configuration rules.

## ⚙️ Methodology / Approach
To build a reliable detection engine, I focused on **Stateful Packet Correlation**:
- **Rule Ingestion:** Designed a parser to read standard `knockd.conf` files to establish the "ground truth" for valid signatures.
- **Traffic Grouping:** Implemented a system to group incoming packets by Source/Destination IP pairs to track individual connection attempts.
- **Sliding Window Validation:** Created a logic loop that scans through packet history to find sub-sequences that match the configuration.
- **Temporal Verification:** Calculated time deltas between the first and last "knock" to ensure the sequence occurred within the required `seq_timeout`.

## 🛠️ Tools & Technologies
- **Python 3.x:** Core development language.
- **dpkt:** High-performance library used for Deep Packet Inspection (DPI) and binary PCAP parsing.
- **knockd:** The Linux daemon used to configure the port knocking service.
- **Iptables:** The Linux firewall used to maintain the "stealth" port state.
- **Netcat (nc):** Used to generate the knock sequences during testing.

## 💻 Implementation / Steps
The implementation is contained in `dg0099.py`, which bridges the gap between raw data and security alerts.

### 1. Parsing the Signature Configuration
The script dynamically reads `knockd.conf` to learn which port sequences to monitor.
```python
# Extracting sequences and timeouts from config
for section in config.sections():
    if 'sequence' in config[section]:
        ports = list(map(int, config[section]['sequence'].split(',')))
        timeout = int(config[section]['seq_timeout'])
```
### 2. Forensic Packet Analysis
The engine iterates through the PCAP, extracting TCP SYN packets and tracking the timing of each hit.

```python
# Tracking hits per host pair
if isinstance(ip.data, dpkt.tcp.TCP):
    tcp = ip.data
    # Filter for SYN packets only (the 'knock')
    if tcp.flags & dpkt.tcp.TH_SYN:
        knocks[(src, dst)].append((ts, tcp.dport))
```
### 3. Sequence Matching Logic
A sliding window algorithm is used to compare the recorded packet hits against the expected sequence defined in the configuration. This ensures that the engine can detect a valid knock even if it is surrounded by other network traffic.

``` python
    for i in range(len(knock_list) - len(ports) + 1):
    # 'zip' extracts the timestamps and port numbers for the current window
    times, ports_found= zip(*knock_list[i:i+len(ports)]) 
   
    # Validation: Match sequence AND verify it occurred within the timeout window
    if list(ports_found) == ports and (times[-1] - times[0] <= timeout):
        print(f"Detected {name} sequence from {host}") 
```
        
# 🧪 How to Test

1. **Install Dependencies:** ``` pip install dpkt ```

2. **Run the Detector:** ``` python3 dg0099.py -i <capture_file>.pcap ```

## 📊 Results / Findings
The script was validated against the provided `netlog.pcap` file. The engine successfully reconstructed the timeline of events, identifying both the authorization (open) and de-authorization (close) sequences.

| Service Name | Port Sequence Identified | Result | Detection Status |
| :--- | :--- | :--- | :--- |
| **openSSH** | 7000, 8000, 9000 | Sequence Match + Valid Timeout | ✅ ALERT TRIGGERED |
| **closeSSH** | 9000, 8000, 7000 | Sequence Match + Valid Timeout | ✅ ALERT TRIGGERED |
| **openHTTPS** | 12345, 54321, 24680, 13579 | No sequence detected in log | ✅ SCAN CLEAN |

### Key Security Insights:
* **Accuracy:** The tool successfully ignored "background noise" packets by requiring an exact sequence match.
* **Temporal Integrity:** By enforcing the `seq_timeout`, the engine ensures that random port hits over a long period are not falsely identified as valid knocks.
* **Automation:** This logic effectively functions as an automated forensic auditor, turning thousands of raw packets into a few lines of actionable security alerts.

## 🖼️ Screenshots / Diagrams 

### 1. Architecture
<img width="800" height="550" alt="Arch-Diagram" src="https://github.com/user-attachments/assets/1d9a603d-eb29-4398-a736-4a31ad33a073" />

### 2. Terminal Output
<img width="700" height="100" alt="1" src="https://github.com/user-attachments/assets/eb88ccfa-3730-41a9-a8f0-43d469eadfcc" />

## 💡 Challenges & Lessons Learned

- **Stateful vs. Stateless Detection:** One of the primary challenges was moving beyond simple packet filtering. I learned that detecting sequences requires **Stateful Inspection** the engine must maintain a memory of previous events per IP to correlate them over time.
    
- **Managing "Network Noise":** In real-world PCAPs, valid knocks are often buried between unrelated traffic. Implementing a **sliding window algorithm** was critical to ensure the detector didn't break if a non-knock packet arrived in the middle of a sequence.
  



