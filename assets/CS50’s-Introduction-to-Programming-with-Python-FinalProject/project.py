import csv
import pyshark

def main():
    # changing pcapng file to csv file
    convert_to_csv('traffic.pcapng', 'traffic.csv')
    # reading packets from csv file
    packets = parse_data('traffic.csv')
    # finding ddos ips and large packets with thresholds
    ddos_ips, large_packets = detect_ddos(packets, packet_count_threshold=10, size_threshold=1500)
    # calculating average packet size
    avg_size = average_size(packets)
    # printing the results
    print(f"DDoS IPs: {ddos_ips}")
    print(f"Large Packets: {len(large_packets)}")
    print(f"Average Size: {avg_size:.2f} bytes")


def convert_to_csv(pcapng_file, csv_file):
    # defining a  csv headers
    headers = ['source_ip', 'destination_ip', 'protocol', 'length']
    # openining pcapng with pyshark
    cap = pyshark.FileCapture(pcapng_file)
    # writing data to csv
    with open(csv_file, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(headers)
        for packet in cap:
            try:
                # trying to get packet info
                source_ip = packet.ip.src
                destination_ip = packet.ip.dst
                protocol = packet.highest_layer
                length = packet.length
                writer.writerow([source_ip, destination_ip, protocol, length])
            except AttributeError:
                continue

def parse_data(csv_file):
    packets = []
    # opening csv and reading data
    with open(csv_file, newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            packets.append(row)
    return packets

def detect_ddos(packets, packet_count_threshold=10, size_threshold=1500):
    ip_counts = {}
    large_packets = []
    for packet in packets:
        source_ip = packet['source_ip']
        # count packets per ip
        if source_ip in ip_counts:
            ip_counts[source_ip] += 1
        else:
            ip_counts[source_ip] = 1
        # to find packets larger than size threshold
        if int(packet['length']) > size_threshold:
            large_packets.append(packet)
    # get ips with packet count over threshold
    ddos_ips = [ip for ip, count in ip_counts.items() if count > packet_count_threshold]
    return ddos_ips, large_packets

def average_size(packets):
    total_size = 0
    packet_count = len(packets)
    for packet in packets:
        # adding up packet sizes
        total_size += int(packet['length'])
    # calculating average size
    return total_size / packet_count if packet_count > 0 else 0

if __name__ == "__main__":
    main()
