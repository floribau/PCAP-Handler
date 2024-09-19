# PCAP Handler
## Network traffic analysis
Extracts information from the packets stored in a specified pcap file. Since I couldn't use any Python pcap library, I used the defined structure of these packets by reading the corresponding numbers of bytes to extract the information.
## Scanning / Probing detection
Detects scanning or probing done from a specified IP address. A probing is characterized as a collection of points with identical port numbers grouped closely together in the time dimension. Conversely, a scanning comprises a group of points that share the same port space.  
To run the file scanning_probing_detection.py, the following parameters have to specified:  
-f file_path -t target_ip -l width_probing -m min_packets_probing -n width_scanning -p min_packets_scanning  
Example command: python scanning_probing_detection.py -f scanning1.pcap -t 192.168.2.26 -l 3 -m 4 -n 10 -p 4
