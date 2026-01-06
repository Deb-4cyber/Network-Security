import dpkt
import argparse

def count_packets(filename):
    with open(filename, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)

        null_count = 0
        xmas_count = 0
        udp_count = 0
        half_open_count = 0
        connect_count = 0

        for timestamp, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            if isinstance(eth.data, dpkt.ip.IP):
                ip = eth.data
                if isinstance(ip.data, dpkt.tcp.TCP):
                    tcp = ip.data
                    if tcp.flags == 0:  # Null scan
                        null_count += 1
                    elif tcp.flags == dpkt.tcp.TH_FIN | dpkt.tcp.TH_URG | dpkt.tcp.TH_PUSH:  # XMAS scan
                        xmas_count += 1
                    elif tcp.flags == dpkt.tcp.TH_SYN:  # Half-open scan
                        half_open_count += 1
                    elif tcp.flags == dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK:  # Connect scan
                        connect_count += 1
                elif isinstance(ip.data, dpkt.udp.UDP):  # UDP scan
                    udp_count += 1

        print(f"Null: {null_count}")
        print(f"XMAS: {xmas_count}")
        print(f"UDP: {udp_count}")
        print(f"Half-open: {half_open_count}")
        print(f"Connect: {connect_count}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input", help="Input PCAP file", required=True)
    args = parser.parse_args()

    count_packets(args.input)
