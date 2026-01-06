# 📌 Port Scan Detection Engine

![Python](https://img.shields.io/badge/python-3.x-green.svg)

## 📝 Overview
This project contains a specialized network security tool I developed to automate the detection of various Nmap port scanning techniques. By utilizing the `dpkt` library, the script parses raw packet data from `.pcap` files to identify and categorize scanning signatures. This project demonstrates my ability to translate network protocol theory into functional Python code for security analysis.

## ⚙️ Methodology / Approach
To build this detector, I focused on identifying specific TCP flag combinations and transport layer protocols that characterize different scanning behaviors:
1.  **Bitwise Flag Analysis:** I mapped the TCP header flags (FIN, URG, PUSH, SYN, ACK) to the bitmasks defined in the `dpkt` library.
2.  **Protocol Filtering:** I implemented checks to ensure the script only processes IP packets, further drilling down into TCP or UDP payloads as needed.
3.  **Signature Extraction:** I defined the specific logic required to distinguish between stealthy "half-open" scans and standard connection attempts based on the initial handshake packets.

## 🛠️ Tools & Technologies
- **Python 3.x:** The core language used for script development.
- **dpkt:** A fast, lightweight library used for parsing PCAP files and de-encapsulating headers.
- **argparse:** Used to handle command-line arguments for file input.
- **Nmap & Wireshark:** Used to generate the test data and verify the ground truth of the captures.

## 💻 Implementation / Steps
I wrote the script `dg0099.py` to handle the logic in a single, efficient pass through the PCAP file.

### Inside the Script (`dg0099.py`):
My implementation performs the following technical checks for each packet:
- **Null Scan:** Checks if the TCP flag field is exactly `0`.
- **XMAS Scan:** Uses a bitwise **OR** operator (`|`) to verify if the `FIN`, `URG`, and `PSH` flags are all set simultaneously.
- **UDP Scan:** Identifies packets where the IP payload is a UDP object.
- **Half-Open Scan:** Identifies packets where only the `SYN` flag is set.
- **Connect Scan:** Identifies the `SYN + ACK` response, which characterizes a full TCP connect attempt.

### 🔍 Technical Deep Dive: Scan Logic & Protocol Analysis
To detect various scanning signatures, I implemented logic that analyzes both the protocol type and the specific bitmasks within the TCP header.

| Scan Type | Logic / Constants used in `dg0099.py` | Signature Value | Technical Context |
| :--- | :--- | :--- | :--- |
| **UDP** | `isinstance(ip.data, dpkt.udp.UDP)` | N/A | Identified by protocol type (Connectionless). |
| **Null** | `tcp.flags == 0` | `0` | Absence of all TCP control bits. |
| **Half-open**| `tcp.flags == dpkt.tcp.TH_SYN` | `2` | SYN bit set; initiates a "stealth" connection. |
| **Connect** | `tcp.flags == TH_SYN | TH_ACK` | `18` | SYN + ACK; indicates a full handshake attempt. |
| **XMAS** | `TH_FIN | TH_URG | TH_PUSH` | `41` | Multiple "illegal" bits set simultaneously. |

#### Implementation of Bitwise Operators
In the TCP-based detections, I used the bitwise OR (`|`) operator to combine constants from the `dpkt` library. This allows the script to evaluate the 8-bit flag field in a single operation:

```python
# Example: Detecting a full Connect Scan signature (SYN=2, ACK=16)
elif tcp.flags == dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK:
    connect_count += 1

# Example: Detecting an XMAS Scan (FIN=1, PUSH=8, URG=32)
elif tcp.flags == dpkt.tcp.TH_FIN | dpkt.tcp.TH_URG | dpkt.tcp.TH_PUSH:
    xmas_count += 1
```

## 🧪 How to Test
To verify the detector's functionality, follow these steps:

1. **Install Dependencies:** ``` pip install dpkt ```
2. **Run the Detector:** Use the provided sample PCAP files (e.g., null_scan.pcap) to check for specific scans:
   ``` python
       python3 dg0099.py -i <filename>.pcap
   ```
3. **Verify Output:** The terminal will display the counts for each scan type identified in that specific file.

## 📊 Results / Findings
The script successfully processed various PCAP captures, yielding the following packet counts for each respective scan type. These results were validated against Nmap's default scanning behavior and achieved high detection accuracy across all test cases.

| Scan Type | PCAP File Tested | Packets Detected | Description |
| :--- | :--- | :--- | :--- |
| **XMAS** | `xmas_scan.pcap` | **263,678** | Identified via FIN, PSH, and URG flags. |
| **Null** | `null_scan.pcap` | **263,063** | Identified by the absence of all TCP flags. |
| **UDP** | `udp_scan.pcap` | **77,796** | Detected by identifying UDP protocol objects. |
| **Half-open** | `half-open_scan.pcap`| **139,292** | Identified by SYN flag presence without ACK. |
| **Connect** | `connect_scan.pcap` | **46** | Differentiated by identifying the SYN+ACK response. |

**Key Insight:** The high packet counts demonstrate the script's capability to handle large-scale reconnaissance data efficiently.

## 🖼️ Screenshots / Diagram

### 1. Architecture Diagram
   <img width="800" height="400" alt="Arch-Diagram" src="https://github.com/user-attachments/assets/dcf2ef34-81f2-4cef-bfed-b225aea8d69b" />

### 2. Terminal Output

Figure 1: Detection results for Connect, Half-open, Null, and UDP scan captures. 
<img width="750" height="425" alt="1" src="https://github.com/user-attachments/assets/a9fa145a-b9a1-4b62-8296-8c7b0dcd6027" />

Figure 2: Detection results for XMAS scan capture. 
<img width="800" height="226" alt="2" src="https://github.com/user-attachments/assets/bb3c1e30-6cd1-48a2-a60a-da5b753af959" />

## 💡 Challenges & Lessons Learned
- **Handshake Differentiation:** Differentiating between Half-Open and Connect scans required targeting the specific `SYN+ACK` signature to identify completed connection attempts.
- **Flag Logic:** Learned how Nmap exploits TCP state machines, specifically using "illegal" flag combinations like XMAS to elicit responses from diverse OS kernels.
- **Large-Scale Processing:** Gained experience using `dpkt.pcap.Reader` for memory-efficient iteration, allowing for the successful parsing of a 126MB UDP capture file without overhead.
- **Bitwise Mastery:** Practiced using bitwise OR (`|`) operators to create precise packet filters, an essential skill for low-level network security programming.

