# Packet Sniffer, wireshark like utility

Packet sniffer utility written in C

- Captures Ethernet headers
- Captures IP (IPv4) headers
- Captures TCP, UDP, ICMP, IGMP headers

## Output example

     ETHERNET HEADER:
	|-Source Address : 95-25-23-E9-FD-A1
	|-Destination Address : FA-A3-A7-96-E1-6F
	|-Protocol : 0x800		IPv4 Protocol

	IPv4 HEADER:

	|-Version : 4
	|-Internet Header Length : 5 DWORDS or 20 Bytes
	|-Type Of Service : 0
	|-Total Length : 105 Bytes
	|-Identification : 5046
	|-Time To Live : 120
	|-Protocol : 6 Protocol name : tcp
	|-Header Checksum : 7806
	|-Source IP : 172.253.118.189
	|-Destination IP : 192.168.43.248

	TCP Header: 

		 |-Source Port      : 443
		 |-Destination Port : 48960
		 |-Sequence Number    : 1816204318
		 |-Acknowledge Number : 2613412817
		 |-Header Length      : 8 DWORDS or 32 BYTES
		 |-Urgent Flag          : 0
		 |-Acknowledgement Flag : 1
		 |-Push Flag            : 1
		 |-Reset Flag           : 0
		 |-Synchronise Flag     : 0
		 |-Finish Flag          : 0
		 |-Window         : 389
		 |-Checksum       : 53069
		 |-Urgent Pointer : 0



