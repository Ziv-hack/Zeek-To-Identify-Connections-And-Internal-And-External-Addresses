This Zeek script is designed to monitor and analyze network connections in real time or from a captured pcap file. It focuses on the first ten newly established connections,
printing structured details such as the source and destination IP addresses, ports, transport protocol (TCP, UDP, or ICMP), connection ID, 
and the exact time the connection began. 
The script uses a custom record type to store these fields neatly—similar to a data class in Kotlin—making the output both organized and human-readable.

Beyond basic connection tracking, the script also identifies and categorizes all unique IP addresses encountered. 
It maintains a set of these addresses and checks each one against a predefined list of local subnets to determine whether it belongs to the internal network or is external. 
This makes the script not only a connection logger but also a simple network-mapping and classification tool, 
useful for understanding which systems communicate within or outside your local environment.
