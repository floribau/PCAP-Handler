file = "pcap_files/file1.pcap"

with open("log/log_network_traffic_analysis.txt", 'a') as log:
    log.write("-" * 30 + "\n")
    log.write(f"Analysis of file {file}\n")
    log.write("-" * 30 + "\n")
    packet_count = 0
    with open(file, 'rb') as pcap_file:

        # skip global header (24 bytes)
        pcap_file.read(24)

        while True:
            # read packet header (16 bytes)
            header = pcap_file.read(16)
            if len(header) < 16:
                # end of file
                break

            packet_count += 1
            log.write(f"Packet {packet_count}:\n")

            # get packet length from packet header (incl_len)
            packet_length = int.from_bytes(header[8:12], byteorder='little')

            # read packet data
            packet_data = pcap_file.read(packet_length)

            # get source ip from packet data
            source_ip = '.'.join(map(str, packet_data[26:30]))
            log.write(f"Source IP address: {source_ip}\n")

            # get destination TCP port from packet data if it is a TCP packet
            if packet_data[23] == 6:
                destination_port = int.from_bytes(packet_data[36:38], byteorder='big')
                log.write(f"Destination TCP port: {destination_port}\n")
            log.write("\n")
    log.write("\n")
