from sniffer import Sniffer
import pcapy
import argparse
import sys
import threading
import time
import os


def main():
    parser = argparse.ArgumentParser(description="Сетевой сниффер")
    parser.add_argument(
        "-i",
        "--interface",
        help="Интерфейсы для прослушивания",
        required=False,
        nargs="+",
    )
    parser.add_argument("-o", "--output", help="Путь к выходному файлу PCAP")
    parser.add_argument(
        "-f", "--filter", help="Строка фильтра BPF (например, 'tcp port 80')"
    )
    parser.add_argument(
        "-l",
        "--list-interfaces",
        action="store_true",
        help="Вывести список доступных интерфейсов",
    )
    parser.add_argument("bpf_filter", nargs="*", help="Выражение фильтра BPF")

    args = parser.parse_args()

    interfaces = pcapy.findalldevs()

    if args.list_interfaces:
        print("Доступные интерфейсы:")
        for iface in interfaces:
            print(f" - {iface}")
        sys.exit(0)

    target_interfaces = args.interface
    if not target_interfaces:
        if not interfaces:
            print("Интерфейсы не найдены.")
            sys.exit(1)
        print(f"Интерфейс не указан, используется по умолчанию: {interfaces[0]}")
        target_interfaces = [interfaces[0]]

    for iface in target_interfaces:
        if iface not in interfaces:
            print(
                f"Предупреждение: Интерфейс '{iface}' может отсутствовать в списке обнаруженных. Доступные: {interfaces}"
            )

    filter_parts = []
    if args.filter:
        filter_parts.append(args.filter)
    if args.bpf_filter:
        filter_parts.extend(args.bpf_filter)

    final_filter = " ".join(filter_parts).strip()
    if final_filter:
        print(f"Фильтр: {final_filter}")

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
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nОстановка всех сессий захвата...")
        sys.exit(0)


if __name__ == "__main__":
    main()
