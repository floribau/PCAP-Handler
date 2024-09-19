import sys
from datetime import datetime

# check if number of args correct, end program if not
if len(sys.argv) != 13:
    print("Usage: python scanning_probing_detection.py -f file_path -t target_ip -l width_probing "
          "-m min_packets_probing -n width_scanning -p min_packets_scanning")
    sys.exit(1)

# initialize file path, target ip, widths and minimum numbers of packets with values specified in args
if sys.argv[1] == "-f":
    file_path = "pcap_files/" + sys.argv[2]
else:
    print("Usage: python scanning_probing_detection.py -f file_path -t target_ip -l width_probing "
          "-m min_packets_probing -n width_scanning -p min_packets_scanning")
    sys.exit(1)

if sys.argv[3] == "-t":
    target_ip = sys.argv[4]
else:
    print("Usage: python scanning_probing_detection.py -f file_path -t target_ip -l width_probing "
          "-m min_packets_probing -n width_scanning -p min_packets_scanning")
    sys.exit(1)

if sys.argv[5] == "-l":
    width_probing = sys.argv[6]
else:
    print("Usage: python scanning_probing_detection.py -f file_path -t target_ip -l width_probing "
          "-m min_packets_probing -n width_scanning -p min_packets_scanning")
    sys.exit(1)

if sys.argv[7] == "-m":
    min_packets_probing = sys.argv[8]
else:
    print("Usage: python scanning_probing_detection.py -f file_path -t target_ip -l width_probing "
          "-m min_packets_probing -n width_scanning -p min_packets_scanning")
    sys.exit(1)

if sys.argv[9] == "-n":
    width_scanning = sys.argv[10]
else:
    print("Usage: python scanning_probing_detection.py -f file_path -t target_ip -l width_probing "
          "-m min_packets_probing -n width_scanning -p min_packets_scanning")
    sys.exit(1)

if sys.argv[11] == "-p":
    min_packets_scanning = sys.argv[12]
else:
    print("Usage: python scanning_probing_detection.py -f file_path -t target_ip -l width_probing "
          "-m min_packets_probing -n width_scanning -p min_packets_scanning")
    sys.exit(1)


def extract_targeting_packets(file, ip):
    # extract packets that have the specified target_ip as source ip address
    targeting_packets = []
    with open(file, 'rb') as pcap_file:

        # skip global header (24 bytes)
        pcap_file.read(24)

        while True:
            # read packet header (16 bytes)
            header = pcap_file.read(16)
            if len(header) < 16:
                break  # end of file

            # get packet length from packet header (incl_len)
            packet_length = int.from_bytes(header[8:12], byteorder='little')

            # calculate timestamp (ts_sec + ts_usec)
            time_stamp_secs = int.from_bytes(header[0:4], byteorder='little')
            time_stamp_microsecs = int.from_bytes(header[4:8], byteorder='little')
            time_stamp = datetime.fromtimestamp(time_stamp_secs + time_stamp_microsecs / 10 ** 6)

            # read packet data
            packet_data = pcap_file.read(packet_length)

            # get destination ip from packet data
            destination_ip = '.'.join(map(str, packet_data[30:34]))

            # check if destination_ip = target_ip and protocol either TCP or UDP
            if destination_ip == ip and (packet_data[23] == 6 or packet_data[23] == 17):
                # extract source ip, protocol, destination port and time stamp from the packet data
                source_ip = '.'.join(map(str, packet_data[26:30]))
                protocol = packet_data[23]
                destination_port = int.from_bytes(packet_data[36:38], byteorder='big')
                # add tuple (source_ip, protocol, destination_port, time_stamp) to targeted_packets
                targeting_packets.append([source_ip, protocol, destination_port, time_stamp])
    return targeting_packets


def calc_clusters_probing(protocol, width, min_packets):
    # calc clusters for probing:
    # compare each packet in targeting_packets with existing clusters
    # if packet meets criteria to belong to a cluster: add packet
    # if not: packet opens own cluster
    clusters = []

    for packet in packets:
        found_cluster = False
        if packet[1] == protocol:
            for cluster in clusters:
                for clustered_packet in cluster:
                    if clustered_packet[0] == packet[0] and clustered_packet[2] == packet[2] and abs(
                            (clustered_packet[3] - packet[3]).total_seconds()) < float(width):
                        cluster.append(packet)
                        found_cluster = True
                        break
            if not found_cluster:
                clusters.append([packet])

    # remove clusters that include less than min_packets packets
    clusters = [cluster for cluster in clusters if len(cluster) >= int(min_packets)]
    return clusters


def calc_clusters_scanning(protocol, width, min_packets):
    # calc clusters for scanning:
    # compare each packet in targeting_packets with existing clusters
    # if packet meets criteria to belong to a cluster: add packet
    # if not: packet opens own cluster
    clusters = []
    for packet in packets:
        found_cluster = False
        if packet[1] == protocol:
            for cluster in clusters:
                for clustered_packet in cluster:
                    if clustered_packet[0] == packet[0] and abs(clustered_packet[2] - packet[2]) < float(width):
                        cluster.append(packet)
                        found_cluster = True
                        break
            if not found_cluster:
                clusters.append([packet])

    # remove clusters that include less than min_packets packets
    clusters = [cluster for cluster in clusters if len(cluster) >= int(min_packets)]
    return clusters


packets = extract_targeting_packets(file_path, target_ip)

probing_tcp = calc_clusters_probing(6, width_probing, min_packets_probing)
probing_udp = calc_clusters_probing(17, width_probing, min_packets_probing)
scanning_tcp = calc_clusters_scanning(6, width_scanning, min_packets_scanning)
scanning_udp = calc_clusters_scanning(17, width_scanning, min_packets_scanning)

with open("log/log_scanning_probing_detection.txt", 'a') as log:
    log.write("-" * 30 + "\n")
    log.write(f"Analysis of file {file_path}\n")
    log.write("-" * 30)
    log.write("\nTarget IP: " + target_ip)
    log.write("\nWidth for probing: " + width_probing + " seconds")
    log.write("\nMinimum number of packets in a probing: " + min_packets_probing)
    log.write("\nWidth for scanning: " + width_scanning + " port IDs")
    log.write("\nMinimum number of packets in a scanning: " + min_packets_scanning)

    log.write("\n\nReports of probing with TCP:")
    for report in probing_tcp:
        log.write("\n>Probing from " + report[0][0] + " to Port " + str(report[0][2]) + " - Total attempts: " + str(
            len(report)))
    if len(probing_tcp) == 0:
        log.write("\nNo reports found.")

    log.write("\n\nReports of probing with UDP:")
    for report in probing_udp:
        log.write("\n>Probing from " + report[0][0] + " to Port " + str(report[0][2]) + " - Total attempts: " + str(
            len(report)))
    if len(probing_udp) == 0:
        log.write("\nNo reports found.")

    log.write("\n\nReports of scanning with TCP:")
    for report in scanning_tcp:
        log.write("\n>Scanning from " + report[0][0] + " - Total attempts: " + str(len(report)))
    if len(scanning_tcp) == 0:
        log.write("\nNo reports found.")

    log.write("\n\nReports of scanning with UDP:")
    for report in scanning_udp:
        log.write("\n>Scanning from " + report[0][0] + " - Total attempts: " + str(len(report)))
    if len(scanning_udp) == 0:
        log.write("\nNo reports found.")

    log.write("\n\n")