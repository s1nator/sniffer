from sniffer import Sniffer
import pcapy
import argparse
import sys
import threading
import time
import os


def main():
    parser = argparse.ArgumentParser(description="Sniffer")
    parser.add_argument(
        "-i", "--interface", help="Interface(s) to sniff on", required=False, nargs="+"
    )
    parser.add_argument("-o", "--output", help="Output PCAP file path")
    parser.add_argument("-f", "--filter", help="BPF Filter string (e.g. 'tcp port 80')")
    parser.add_argument(
        "-l", "--list-interfaces", action="store_true", help="List available interfaces"
    )
    parser.add_argument("bpf_filter", nargs="*", help="BPF Filter expression")

    args = parser.parse_args()

    interfaces = pcapy.findalldevs()

    if args.list_interfaces:
        print("Available interfaces:")
        for iface in interfaces:
            print(f" - {iface}")
        sys.exit(0)

    target_interfaces = args.interface
    if not target_interfaces:
        if not interfaces:
            print("No interfaces found.")
            sys.exit(1)
        print(f"No interface specified, using default: {interfaces[0]}")
        target_interfaces = [interfaces[0]]

    for iface in target_interfaces:
        if iface not in interfaces:
            print(
                f"Warning: Interface '{iface}' might not be in the discovered list. Available: {interfaces}"
            )

    filter_parts = []
    if args.filter:
        filter_parts.append(args.filter)
    if args.bpf_filter:
        filter_parts.extend(args.bpf_filter)

    final_filter = " ".join(filter_parts).strip()
    if final_filter:
        print(f"[*] Filter: {final_filter}")

    threads = []

    for iface in target_interfaces:
        output_file = args.output

        if output_file and len(target_interfaces) > 1:
            base, ext = os.path.splitext(output_file)
            output_file = f"{base}_{iface}{ext}"

        sniffer = Sniffer(iface, output_file, final_filter)

        t = threading.Thread(target=sniffer.start)
        t.daemon = True
        t.start()
        threads.append(t)

    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\n[*] Stopping all sniffing sessions...")
        sys.exit(0)


if __name__ == "__main__":
    main()
