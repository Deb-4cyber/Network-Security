import configparser
import time
import dpkt
import socket
from collections import defaultdict

def parse_knockd_conf(knockd_conf):
    config = configparser.ConfigParser()
    config.read(knockd_conf)
    sequences = dict()
    for section in config.sections():
        if 'sequence' in config[section] and 'seq_timeout' in config[section]:
            sequences[section] = (list(map(int, config[section]['sequence'].split(','))), int(config[section]['seq_timeout']))
    return sequences

def detect_port_knocking(pcap_file, sequences):
    f = open(pcap_file, 'rb')
    pcap = dpkt.pcap.Reader(f)
    knocks = defaultdict(list)
    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        if isinstance(eth.data, dpkt.ip.IP):
            ip = eth.data
            if isinstance(ip.data, dpkt.tcp.TCP):
                tcp = ip.data
                src = socket.inet_ntoa(ip.src)
                dst = socket.inet_ntoa(ip.dst)
                port = tcp.dport
                knocks[(src, dst)].append((ts, port))
    f.close()

    for host, knock_list in knocks.items():
        for name, sequence in sequences.items():
            ports, timeout = sequence[0], sequence[1]
            for i in range(len(knock_list) - len(ports) + 1):
                times, knocks = zip(*knock_list[i:i+len(ports)])
                if list(knocks) == ports and times[-1] - times[0] <= timeout:
                    print(f"Detected {name} sequence from {host[0]} to {host[1]} at {time.ctime(times[0])}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <knockd.conf> <netlog.pcap>")
        sys.exit(1)
    sequences = parse_knockd_conf(sys.argv[1])
    detect_port_knocking(sys.argv[2], sequences)
