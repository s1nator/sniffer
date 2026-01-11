import pcapy
import argparse
import struct
import socket
import sys
import time

def get_mac_addr(bytes_addr):
    return ':'.join(map('{:02x}'.format, bytes_addr))

def parse_ethernet(data):
    eth_header = data[:14]
    eth = struct.unpack('!6s6sH', eth_header)
    dest_mac = get_mac_addr(eth[0])
    src_mac = get_mac_addr(eth[1])
    proto = eth[2]
    return dest_mac, src_mac, proto, data[14:]

def parse_ipv4(data):
    header = struct.unpack('!BBHHHBBH4s4s', data[:20])
    version_ihl = header[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0xF
    iph_length = ihl * 4
    
    ttl = header[5]
    protocol = header[6]
    s_addr = socket.inet_ntoa(header[8])
    d_addr = socket.inet_ntoa(header[9])
    
    return version, iph_length, ttl, protocol, s_addr, d_addr, data[iph_length:]

def parse_tcp(data):
    header = struct.unpack('!HHLLBBHHH', data[:20])
    source_port = header[0]
    dest_port = header[1]
    sequence = header[2]
    acknowledgement = header[3]
    doff_reserved = header[4]
    tcph_length = (doff_reserved >> 4) * 4
    
    return source_port, dest_port, sequence, acknowledgement, data[tcph_length:]

def parse_udp(data):
    header = struct.unpack('!HHHH', data[:8])
    source_port = header[0]
    dest_port = header[1]
    length = header[2]
    
    return source_port, dest_port, length, data[8:]

class Sniffer:
    def __init__(self, interface, output_file=None, pcap_filter=None):
        self.interface = interface
        self.output_file = output_file
        self.pcap_filter = pcap_filter
        self.dumper = None

    def packet_handler(self, header, data):
        if self.dumper:
            self.dumper.dump(header, data)

        ts = header.getts()
        print(f"\n[+] Packet captured at {time.ctime(ts[0])}.{ts[1]} | Length: {header.getlen()}")

        try:
            dest_mac, src_mac, eth_proto, payload = parse_ethernet(data)
            print(f"    Ethernet: {src_mac} -> {dest_mac} | Protocol: {hex(eth_proto)}")

            if eth_proto == 0x0800:
                version, iph_len, ttl, proto, src, target, payload = parse_ipv4(payload)
                print(f"    IPv4: {src} -> {target} | TTL: {ttl} | Protocol: {proto}")
                if proto == 6:
                    src_port, dst_port, seq, ack, _ = parse_tcp(payload)
                    print(f"        TCP: {src_port} -> {dst_port} | Seq: {seq} | Ack: {ack}")
                elif proto == 17:
                    src_port, dst_port, length, _ = parse_udp(payload)
                    print(f"        UDP: {src_port} -> {dst_port} | Length: {length}")
            
            elif eth_proto == 0x0806:
                print("    ARP Packet")

        except Exception as e:
            print(f"    Error parsing packet: {e}")

    def start(self):
        print(f"[*] Starting sniffer on interface {self.interface}")
        
        try:
            cap = pcapy.open_live(self.interface, 65536, 1, 0)
            
            if self.pcap_filter:
                print(f"[*] Setting filter: {self.pcap_filter}")
                cap.setfilter(self.pcap_filter)
                
            if self.output_file:
                print(f"[*] Saving output to {self.output_file}")
                self.dumper = cap.dump_open(self.output_file)
                
            print("[*] Press Ctrl+C to stop")
            cap.loop(0, self.packet_handler)
            
        except pcapy.PcapError as e:
            print(f"Error opening interface: {e}")
            sys.exit(1)
        except KeyboardInterrupt:
            print("\n[*] Stopping sniffer")
            sys.exit(0)

def main():
    parser = argparse.ArgumentParser(description="Simple Python Network Sniffer")
    parser.add_argument("-i", "--interface", help="Interface to sniff on", required=False)
    parser.add_argument("-o", "--output", help="Output PCAP file path")
    parser.add_argument("-f", "--filter", help="BPF Filter string (e.g. 'tcp port 80')")
    parser.add_argument("-l", "--list-interfaces", action="store_true", help="List available interfaces")
    
    args = parser.parse_args()

    interfaces = pcapy.findalldevs()
    
    if args.list_interfaces:
        print("Available interfaces:")
        for iface in interfaces:
            print(f" - {iface}")
        sys.exit(0)

    interface = args.interface
    if not interface:
        if not interfaces:
            print("No interfaces found.")
            sys.exit(1)
        print(f"No interface specified, using default: {interfaces[0]}")
        interface = interfaces[0]

    found = False
    if interface in interfaces:
        found = True
    else:
        print(f"Warning: Interface '{interface}' might not be in the discovered list. Available: {interfaces}")

    sniffer = Sniffer(interface, args.output, args.filter)
    sniffer.start()

if __name__ == "__main__":
    main()