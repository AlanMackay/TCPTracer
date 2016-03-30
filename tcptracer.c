#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <pcap.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>	
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define MAX_IP_LEN 16
#define MAX_NUM_CONNECTION 500
#define SIZE_ETHERNET 14
#define MAX_FILTER_SIZE 200

struct round_trip{
	struct timeval t;
	u_int32_t sequence;
	int data_len;
};

struct tcp_connection{
	struct in_addr ip_src;
	u_int16_t port_src;
	struct in_addr ip_dst;
	u_int16_t port_dst;
};

struct connection {
	u_char ip_src[MAX_IP_LEN]; /*source ip*/
	u_char ip_dst[MAX_IP_LEN]; /*destination ip*/
	u_int16_t port_src;	/*source port number*/
	u_int16_t port_dst;	/*destination port number*/
	int syn_count;		/*flag count*/
	int fin_count;
	int rst_count;
	struct timeval starting_time;
	struct timeval ending_time;
	double duration;
	int num_packet_src;	/*number of packets sent out by source*/
	int num_packet_dst; /*number of packets sent out by destination*/
	int num_total_packets;
	int cur_data_len_src; /*num data bytes*/
	int cur_data_len_dst;
	int cur_total_data_len;
	uint16_t sum_win_size;
	uint16_t min_win_size;
	uint16_t max_win_size;
	int numPackets;
	struct round_trip rtt_ary_src[MAX_NUM_CONNECTION/4]; /*assume 1000*/
	int rtt_ary_src_len; /*the size of the rtt_ary_src array*/
	struct round_trip rtt_ary_dst[MAX_NUM_CONNECTION/4]; /*assume 1000*/
	int rtt_ary_dst_len; /*the size of the rtt_ary_dst array*/
	int is_set;
};

int findConnections(const unsigned char *packet, unsigned int caplen, struct tcp_connection cons[MAX_NUM_CONNECTION], int size);
void openConnection(struct tcp_connection *con, struct connection *connection, char *capFile, struct timeval *startTime);
void printout(int size, struct connection cons[MAX_NUM_CONNECTION]);

int main(int argc, char *argv[]){
	//decalre the required variables
	char errbuf[PCAP_ERRBUF_SIZE];
	char *capFile;
	unsigned int packet_counter=0;
	struct pcap_pkthdr header;
	const u_char *packet;
	int num_connections = 0;
	struct connection connections[MAX_NUM_CONNECTION];
	struct bpf_program fp;

	// Check if there is an argument provided with the program
	if(argc < 2){
		fprintf(stderr, "Please provide a trace file in the arguments\n");
		return(0);
	}

	capFile = argv[1]; // The name of the capture file

	pcap_t *handle;
	handle = pcap_open_offline(capFile, errbuf); //Open the capture file
	if(handle == NULL) {//Check if the file opened correctly
		fprintf(stderr, "Couldn't open pcap file %s: %s\n", capFile, errbuf);
		return(2);
	}

	if(pcap_compile(handle, &fp, "ip and tcp", 0, 0) == -1){//Try to compile the filter
		fprintf(stderr, "Couldn't compile filter 'ip and tcp'");
		return(2);
	}

	if(pcap_setfilter(handle, &fp) == -1){ // Try to apply the filter
		fprintf(stderr, "Coulnd't set the comiled filter");
		return(2);
	}

	//make an array of tcp connection structs
	struct tcp_connection cons[MAX_NUM_CONNECTION];\
	int size = 0;
	struct timeval startTime;
	int first = 1;

	// go through all the packets in the capture file
	while(packet = pcap_next(handle,&header)) {
		if(first){ //grab the start time
		    startTime = header.ts;
		    first = 0;
		} 
		// call findConnections and get how many connectiosn there are
		size = findConnections(packet, header.len, cons, size);
	}
	int i;
	for(i = 0; i < size; i++){
		//Go through each connection and call openConnection on it to get it's info
		openConnection(&cons[i], &connections[i], capFile, &startTime);
	}
	//Close the capture file
	pcap_close(handle);

	//print the results
	printout(size, connections);

	return 0;
}

/* This function takes the 4-tuple which describes a tcp connection and creates a filter 
** to grab all the packets relative to that specific connection.  Then all the required data
** is retrieved from the connection
*/
void openConnection(struct tcp_connection *con, struct connection *connection, char *capFile, struct timeval *startTime){
	// Get the ip addresses into strings
	struct in_addr src_addr = con->ip_src;
	struct in_addr dst_addr = con->ip_dst;
	char srcstr[INET_ADDRSTRLEN];
	char dststr[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &src_addr, srcstr, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &dst_addr, dststr, INET_ADDRSTRLEN);

	char fullFilterStr[400];
	memset(fullFilterStr, 0, sizeof fullFilterStr);
	char filterStart[] = "ip and tcp and ";
	char filter1[MAX_FILTER_SIZE];
	char filter2[MAX_FILTER_SIZE];

	// Put the tuples into a filter format
	sprintf(filter1, "(src port %d and dst port %d and src host %s and dst host %s)", ntohs(con->port_src), ntohs(con->port_dst), srcstr, dststr);
	sprintf(filter2, "(src port %d and dst port %d and src host %s and dst host %s)", ntohs(con->port_dst), ntohs(con->port_src), dststr, srcstr);
	
	// construct the filter
	strncat(fullFilterStr, filterStart, strlen(filterStart));
	strncat(fullFilterStr, "(", 2);
	strncat(fullFilterStr, filter1, strlen(filter1));
	strncat(fullFilterStr, " or ", 5);
	strncat(fullFilterStr, filter2, strlen(filter2));
	strncat(fullFilterStr, ")", 2);

	// start copying information into the connection struct
	strcpy(connection->ip_src, srcstr);
	strcpy(connection->ip_dst, dststr);
	connection->port_src = con->port_src;
	connection->port_dst = con->port_dst;

	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	const u_char *packet;
	struct pcap_pkthdr header; 
	int first = 1;

	// Open the capture file
	pcap_t *handle;
	handle = pcap_open_offline(capFile, errbuf);

	// Check if it opened successfully
	if(handle == NULL){
		fprintf(stderr, "Couldn't open pcap file %s: %s\n", capFile, errbuf);
		exit(1);
	}

	// Try to compile the constructed filter
	if(pcap_compile(handle, &fp, fullFilterStr, 0, 0) == -1){
		fprintf(stderr, "Couldn't compile filter: %s", fullFilterStr);
		exit(1);
	}

	// try to set the compiled fileter on the capture file 
	if(pcap_setfilter(handle, &fp) == -1){
		fprintf(stderr, "Couldn't set filter: %s", fullFilterStr);
		exit(1);
	}

	connection->numPackets = 0;
	connection->min_win_size = 0;
	connection->max_win_size = 0;
	connection->sum_win_size = 0;

	// Open each packet in the specified tcp connection
	while(packet = pcap_next(handle, &header)){
		struct ip *ip;
		struct tcphdr *tcp;
		unsigned int IP_header_length;

		unsigned int caplen = header.len;

		// check if the header is the size of a ethernet header 
		if(caplen < sizeof(struct ether_header)){
			fprintf(stderr, "Ethernet header too short");
			return;
		}

		// step over the ethernet header and adjust the capture length
		packet += sizeof(struct ether_header);
		caplen -= sizeof(struct ether_header);

		// Check if the head is the size of an ip header
		if(caplen < sizeof(struct ip)){
			fprintf(stderr, "IP header too short");
			return;
		}

		// assign the ip header to a struct
		ip = (struct ip*) packet;
		IP_header_length = ip->ip_hl * 4;

		// check if check the the header is the size of this specific ip header
		if(caplen < IP_header_length){
			fprintf(stderr, "Didn't capture full IP header");
			return;
		}
		// Check if the packet is using the tcp protocol
		if(ip->ip_p != IPPROTO_TCP){
			fprintf(stderr, "non-tcp packet");
			return;
		}

		// step over the ip header
		packet += IP_header_length;
		caplen -= IP_header_length;

		// check if the tcp header was captured
		if(caplen < sizeof(struct tcphdr)){
			fprintf(stderr, "TCP header too short");
			return;
		}

		// assign the tcp header section of the packet to a tcp struct
		tcp = (struct tcphdr*) packet;

		// adjust the caplen appropriately
		caplen -= tcp->th_off * 4;

		// Check if the RST, SYN, or FIN flags are set 
		if(tcp->th_flags & TH_RST){
		    connection->rst_count++;
		}
		if(tcp->th_flags & TH_SYN){
			connection->syn_count++;
		}
		if(tcp->th_flags & TH_FIN){
			connection->fin_count++;
		}	

		// if this is the first packet of the connection, record the timestamp relative to the start time of the capture file
		if(first){
			timersub(&header.ts, startTime, &connection->starting_time); 
			first = 0;
		}
		
		// record the min, max and mean window size
		if(ntohs(tcp->window) < connection->min_win_size) connection->min_win_size = ntohs(tcp->window);
		if(ntohs(tcp->window) > connection->max_win_size) connection->max_win_size = ntohs(tcp->window);
		connection->sum_win_size += ntohs(tcp->window);
		// record the number of packets in the conneciton
		connection->numPackets++;
		// this is potentially the last packet, so record the end time as well
		connection->ending_time = header.ts;
		timersub(&header.ts, startTime, &connection->ending_time); 

		// record the number of packets and the amount of data coming from
		// the source address and the destination address
		if(ip->ip_src.s_addr == con->ip_src.s_addr){
			connection->num_packet_src++;
			connection->cur_data_len_src += caplen;
		}
		if(ip->ip_src.s_addr == con->ip_dst.s_addr){
			connection->num_packet_dst++;
			connection->cur_data_len_dst += caplen;
		}
		
	}
	// calculate the duration, the total packets and the total amount of data transferred in the connection
	struct timeval temp;
	timersub(&connection->starting_time, &connection->ending_time, &temp);
    connection->duration = -1.0 * (temp.tv_sec + temp.tv_usec/1000000.0);
    connection->num_total_packets = connection->num_packet_src + connection->num_packet_dst;
    connection->cur_total_data_len = connection->cur_data_len_src + connection->cur_data_len_dst;
}


/* This function processes a packet and creates a 4-tuple to represent the tcp connection
** and then adds the connection to an array of individual tcp connections unless the connection
** is already represented in the array
*/
int findConnections(const unsigned char *packet, unsigned int caplen, struct tcp_connection cons[MAX_NUM_CONNECTION], int size){
	struct ip *ip;
	struct tcphdr *tcp;
	unsigned int IP_header_length;

	// make sure the packet is the size of an ethernet header
	if(caplen < sizeof(struct ether_header)){
		fprintf(stderr, "Ethernet header too short");
		return -1;
	}

	// advance along the packet past the ethernet header
	packet += sizeof(struct ether_header);
	caplen -= sizeof(struct ether_header);

	// check that the current header is the appropriate size for an ip header
	if(caplen < sizeof(struct ip)){
		fprintf(stderr, "IP header too short");
		return -1;
	}

	// Assign the ip struct to the packet as an ip header
	ip = (struct ip*) packet;
	IP_header_length = ip->ip_hl * 4;

	// check that the current header is an appropriate size for the actual size of the ip header
	if(caplen < IP_header_length){
		fprintf(stderr, "Didn't capture full IP header with options");
		return -1;
	}

	// Check that the packet is using the tcp protocol
	if(ip->ip_p != IPPROTO_TCP){
		fprintf(stderr, "non-tcp packet");
		return -1;
	}

	// advance the packet past the IP header
	packet += IP_header_length;
	caplen -= IP_header_length;

	// Check that the current packet is an appropriate size for a tcp header
	if(caplen < sizeof(struct tcphdr)){
		fprintf(stderr, "TCP header too short");
		return -1;
	}

	// grab the tcp header
	tcp = (struct tcphdr*) packet;

	int i;

	// if there are no connections in the cons array, make this the first one
	if(size == 0){
		cons[0].ip_src = ip->ip_src;
		cons[0].port_src = tcp->th_sport;
		cons[0].ip_dst = ip->ip_dst;
		cons[0].port_dst = tcp->th_dport;
	}else{
		//check the array and see if the current connection is already represented
		for(i = 0; i < size; i++){
			if((ip->ip_src.s_addr == cons[i].ip_src.s_addr
				&& tcp->th_sport == cons[i].port_src
				&& ip->ip_dst.s_addr == cons[i].ip_dst.s_addr
				&& tcp->th_dport == cons[i].port_dst)
				|| (ip->ip_dst.s_addr == cons[i].ip_src.s_addr
				&& tcp->th_dport == cons[i].port_src
				&& ip->ip_src.s_addr == cons[i].ip_dst.s_addr
				&& tcp->th_sport == cons[i].port_dst)){
				return size;
			}
		}
		// assign the current connection to the last spot in the array	
		cons[size].ip_src = ip->ip_src;
		cons[size].port_src = tcp->th_sport;
		cons[size].ip_dst = ip->ip_dst;
		cons[size].port_dst = tcp->th_dport;
	}

	return size + 1;
	
}

/*
** this function prints out the information about the capture file and all the details of the individual connections
*/
void printout(int size, struct connection cons[MAX_NUM_CONNECTION]){
	int i;
	struct timeval duration;
	int complete = 0;
	int reset = 0;
	int incomplete = 0;	
	double minTime = 0, maxTime = 0, meanTime = 0;
	int minPackets = 0, maxPackets = 0, meanPackets = 0;
	int minWin = 0, maxWin = 0, meanWin = 0;
	int totalPackets = 0;

	printf("A) Total number of connections: %d\n", size);
	printf("---------------------------------------------\n\n");																																

	// print out the information for each tcp connection
	printf("B) Connection's details:\n");
	for(i = 0; i < size; i++){
		// Whether or not the connection is complete, print the source and destination ip address and port
		// and the status (with respect to the amount of SYN and ACK flags it has)
		printf("Connection %d:\n", i + 1);
		printf("Source Address: %s\n", cons[i].ip_src);
		printf("Destination Address: %s\n", cons[i].ip_dst);
		printf("Source Port: %d\n", ntohs(cons[i].port_src));
		printf("Destination Port: %d\n", ntohs(cons[i].port_dst));
		printf("Status: S%dF%d\n", cons[i].syn_count, cons[i].fin_count);
		if(cons[i].rst_count>0) reset++;
		// For complete connections, i.e. ones that have at least one SIN and one FIN flag, print the rest of the info
		if(cons[i].syn_count > 0 && cons[i].fin_count > 0){
			// record the min and max and mean duration
			if(cons[i].duration < minTime || minTime == 0) minTime = cons[i].duration;
			if(cons[i].duration > maxTime) maxTime = cons[i].duration;
			meanTime += cons[i].duration;

			// record the min and max and mean number of packets sent
			if(cons[i].num_total_packets < minPackets || minPackets == 0) minPackets = cons[i].num_total_packets;
			if(cons[i].num_total_packets > maxPackets) maxPackets = cons[i].num_total_packets;
			meanPackets += cons[i].num_total_packets;
			
			//record the min and max and mean window size
			if(cons[i].min_win_size < minWin) minWin = cons[i].min_win_size;
			if(cons[i].max_win_size > maxWin) maxWin = cons[i].max_win_size;
			meanWin += cons[i].sum_win_size;
			totalPackets += cons[i].numPackets;
			
			complete++;
			printf("Start Time: %d.%02d\n", (int)cons[i].starting_time.tv_sec, (int)cons[i].starting_time.tv_usec);
			printf("End Time: %d.%02d\n", (int)cons[i].ending_time.tv_sec, (int)cons[i].ending_time.tv_usec);
			printf("Duration: %f\n", cons[i].duration);
			printf("Number of packets sent from Source to Destination: %d\n", cons[i].num_packet_src);
			printf("Number of packets sent from Destination to Source: %d\n", cons[i].num_packet_dst);
			printf("Total number of packets: %d\n", cons[i].num_total_packets);
			printf("Number of data bytes sent from Source to Destination: %d\n", cons[i].cur_data_len_src);
			printf("Number of data bytes sent from Destination to Source: %d\n", cons[i].cur_data_len_dst);
			printf("Total number of data bytes: %d\n", cons[i].cur_total_data_len);
		}
		if(cons[i].fin_count == 0) incomplete++;
		printf("END\n");
		printf("+++++++++++++++++++++++++++++\n");
	}

	// Print the general statistics about the connections

	printf("\nC) General\n\n");

	printf("Number of complete connections: %d\n", complete);
	printf("Number of reset connections: %d\n", reset);
	printf("Number of TCP connections that were still open when the trace capture ended: %d\n\n", incomplete);

	// Print the specific statistics about the connections

	printf("D) Complete TCP Connections:\n\n");
	printf("Minimum time durations: %f\n", minTime);
	printf("Mean time durations: %f\n", meanTime/complete);
	printf("Maximum time durations: %f\n\n", maxTime);

	printf("Minimum number of packets including both sent/received: %d\n", minPackets);
	printf("Mean number of packets including both sent/received: %d\n", meanPackets/complete);
	printf("Maximum number of packets including both sent/received: %d\n\n", maxPackets);

	printf("Minimum windows size including both sent/received: %d\n", minWin);
	printf("Mean window size including both sent/received: %d\n", meanWin/totalPackets);
	printf("Maximum window size including both sent/received: %d\n\n", maxWin);
}