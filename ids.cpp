#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <sstream>
#include <fstream>
#include <pcap.h>
#include <linux/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <netdb.h>
#include <sys/time.h>
#include <map>
#include <vector>
#include <utility>

 
using namespace std;

#define SIZE_ETHERNET 14
#define NI_MAXSERV    32
#define NI_MAXHOST  1025

struct DNS_HEADER
{
    unsigned short id; // identification number
 
    unsigned char rd :1; // recursion desired
    unsigned char tc :1; // truncated message
    unsigned char aa :1; // authoritive answer
    unsigned char opcode :4; // purpose of message
    unsigned char qr :1; // query/response flag
 
    unsigned char rcode :4; // response code
    unsigned char cd :1; // checking disabled
    unsigned char ad :1; // authenticated data
    unsigned char z :1; // its z! reserved
    unsigned char ra :1; // recursion available
 
    unsigned short q_count; // number of question entries
    unsigned short ans_count; // number of answer entries
    unsigned short auth_count; // number of authority entries
    unsigned short add_count; // number of resource entries
};


bool inRange(string s) {
	string n;
	stringstream ss1, ss2;
	int find1, find2;
	int ip1, ip2;
	
	find1 = s.find(".");
	n = s.substr(0,find1);
	ss1 << n;
	ss1 >> ip1;
	
	find2 = s.find(".", find1+1);
	n = s.substr(find1+1, find2-find1-1);
	ss2 << n;
	ss2 >> ip2;
	
	if(ip1 != 172) return false;
	else if(ip2 > 31 || ip2 < 16) return false;
	else return true;
}

bool inDomain(string s) {
	ifstream Myfile;
	Myfile.open ("domains.txt");

	if(Myfile.is_open()) {
		while(!Myfile.eof()) {
			string line;
			getline(Myfile,line);
			//cout << s << " --- " << line << endl;
			//cout << s.length() << " --- " << line.length() << endl;
			if (s.length() == line.length()) {
				int match = 1;
				for(int i=0; i < s.length(); i++) {
					if(s[i] != line[i]) {
						//cout << s[i] << " --- " << line[i] << endl;
						match = 0;
						break;
					}
				}
				if(match) {
					//cout << "matched!!!!!!" << endl;
					return true;
				}
			}
		}
		Myfile.close();
	} else {
		cout << "fail to open file" << endl;
	}

	return false;	
}
 
int main(int argc, char *argv[]) {

	// Get a file nam
    string path(argv[1]);
 
    char errbuff[256];
 
	// Open the file and store result in pointer to pcap_t
    pcap_t * pcap = pcap_open_offline(path.c_str(), errbuff);
  
    // Create a header object:
    struct pcap_pkthdr *header;
 
    // Create a character array using a u_char
    const u_char *data;
 
	// Loop through packets and print them to screen
    u_int packetCount = 0;
	u_int packetSize = 0;
	suseconds_t t = 0;
	suseconds_t first = 0;
	
	map<pair<string,string>, suseconds_t> src_dest_time;
	map<string, vector<string> > source_dest;
	
	map<pair<string, pair<string, int> >, suseconds_t> tcp_src_dest_time;
	map<string, vector<pair<string, int> > > tcp_source_dest;
	
	
    while(int returnValue = pcap_next_ex(pcap, &header, &data) >= 0) {

		
		/*-------------------------
		--------------------------- Anomaly detection
		-------------------------*/		
		packetCount++;
		packetSize += (int) header->len;
		
		/*-------------------------
		--------------------------- Spoofed packets
		-------------------------*/
		const struct ether_header* ethernetHeader;
		const struct ip* ipHeader;
		const struct tcphdr* tcpHeader;
		const struct udphdr *udpheader;
		const struct DNS_HEADER *dnsheader;
		char sourceIp[14];
		char destIp[14];
		u_int sourcePort, destPort;
		u_char *buffer;

		ethernetHeader = (struct ether_header *) data;
		ipHeader = (struct ip*)(data + sizeof(struct ether_header));
		inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIp, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &(ipHeader->ip_dst), destIp, INET_ADDRSTRLEN);
			
		if(ipHeader->ip_p == IPPROTO_TCP) {
			tcpHeader = (tcphdr*)(data + sizeof(struct ether_header) + sizeof(struct ip));
			buffer = (u_char*)(data + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));
			sourcePort = ntohs(tcpHeader->source);
			destPort = ntohs(tcpHeader->dest);
				if(!(inRange(sourceIp) || inRange(destIp))) {
					printf("[%s]: src:%s, dst:%s\n", "Spoofed IP address", sourceIp, destIp);
				}
		}else if(ipHeader->ip_p == IPPROTO_UDP) {
			udpheader = (udphdr*)(data + sizeof(struct ether_header) + sizeof(struct ip));
			buffer = (u_char*)(data + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));
			sourcePort = ntohs(udpheader->source);
			destPort = ntohs(udpheader->dest);
				if(!(inRange(sourceIp) || inRange(destIp))) {
					printf("[%s]: src:%s, dst:%s\n", "Spoofed IP address", sourceIp, destIp);
				}
		}
		


		
		/*-------------------------
		--------------------------- Unauthorized servers
		-------------------------*/
		const struct tcphdr *tcpheader;

		if(ipHeader->ip_p == IPPROTO_TCP) {
			
			tcpheader = (struct tcphdr*)(data + sizeof(struct ether_header) + (ipHeader->ip_hl*4));
			if(ipHeader->ip_p == IPPROTO_TCP) {
				if(tcpheader->syn == 1 && tcpheader->ack == 0 && inRange(destIp) && !inRange(sourceIp)) {
					printf("[%s]: rem:%s, srv:%s, port:%d\n", "Attempted server connection", sourceIp, destIp, destPort);
				}
				
				if(tcpheader->ack == 1 && tcpheader->syn == 1 && inRange(sourceIp) && !inRange(destIp)) {
					printf("[%s]: rem:%s, srv:%s, port:%d\n", "Accepted server connection", destIp, sourceIp, sourcePort);
				}			
			}
		}
		
		/*-------------------------
		--------------------------- Known malicious hosts
		-------------------------*/
		u_char *dns_data;
		char query[256];
		
		
		if(ipHeader->ip_p == IPPROTO_UDP) {
			
			udpheader = (udphdr *)(data + sizeof(ether_header) + sizeof(ip));
			
			if (ntohs(udpheader->dest) == 53) {
				dnsheader = (DNS_HEADER *)(data + sizeof(ether_header) + sizeof(ip) + sizeof(udphdr));				
				dns_data = (u_char *)(data + sizeof(ether_header) + sizeof(ip) + sizeof(udphdr) + sizeof(DNS_HEADER));
				int queryLen = ntohs(udpheader->len) - (sizeof(udphdr) + sizeof(DNS_HEADER) + 4 );
				
				int x;
				int offset=0;
				x = (int) dns_data[0];
				
				while(x != 0) {
					for(int i=0; i < x; i++) {
						query[i+offset] = dns_data[i+offset+1];						
					}
					offset += x;
					x = (int) dns_data[offset+1];
					if(x == 0) {
						query[offset] = '\0';
						break;
					} else {
						query[offset] = '.';
						offset++;
					}
				}
				
				string s(query);
				//cout << "size: " << s.size() << endl;
				//cout << s << endl;
				//cout << inDomain(s) << endl;
				if(inDomain(s)) {
					printf("[%s]: src:%s, host:", "Malicious name lookup", sourceIp);
					cout << s << endl;
				}
				
				for(int i=0; i< offset; i++) {
					query[i] = 0;
				}
				s.clear();
			}
		}
		
		/*-------------------------
		--------------------------- Network scanning
		-------------------------*/
		
		if(ipHeader->ip_p == IPPROTO_ICMP) {
			//map<pair<string,string>, suseconds_t> src_dest_time;
			//map<string, vecotr<string> > source_dest;
			
			if (source_dest.count(sourceIp) > 0) { //source has sent packet before
				vector<string> v_dest;
				v_dest = source_dest[sourceIp];
				
				int unique = true;
				for(int i=0; i < v_dest.size(); i++) {
					if(v_dest[i] == destIp) {
						unique = false;
						break;
					}
				}
				
				if(unique) {
					if (v_dest.size() == 9) {
						t = (header->ts).tv_usec;
						string first_dest = v_dest[0];
						pair<string, string> s_d_pair (sourceIp, first_dest);
						first = src_dest_time[s_d_pair];
						if(t - first <= 2000000) {
							printf("[%s]: att:%s\n", "Potential network scan", sourceIp);
						}
						for(int i=0; i < 8; i++) {
							v_dest[i] = v_dest[i+1];
						}
						v_dest[8] = destIp;
						source_dest[sourceIp] = v_dest;
					} else {
						v_dest.push_back(destIp);
						source_dest[sourceIp] = v_dest;	
					}	
				}
			} else { // this is the first time such source send packet
				vector<string> v_dest;
				v_dest.push_back(destIp);
				source_dest[sourceIp] = v_dest;
				pair<string, string> s_d_pair (sourceIp, destIp);
				src_dest_time[s_d_pair] = (header->ts).tv_usec;
			}
		}
		
		if(ipHeader->ip_p == IPPROTO_TCP) {
			//          src         dest    port        time
			//map<pair<string, pair<string, int> >, suseconds_t> tcp_src_dest_time;
			//     src                 dest   port
			//map<string, vector<pair<string, int> > > tcp_source_dest;
			tcpheader = (struct tcphdr*)(data + sizeof(struct ether_header) + (ipHeader->ip_hl*4));
			
			if(tcpheader->syn == 1 && tcpheader->ack == 0) {
				pair<string, int> cur_dest_port (destIp, destPort);
				
				if (tcp_source_dest.count(sourceIp) > 0) { //source has sent packet before
					vector<pair<string, int> > v_dest;
					v_dest = tcp_source_dest[sourceIp];
					
					int unique = true;
					for(int i=0; i < v_dest.size(); i++) {
						
						pair<string, int> dest_port;
						dest_port = v_dest[i];
						
						if((dest_port.first == destIp) && (dest_port.second == destPort)) {
							unique = false;
							break;
						}
					}
					
					if(unique) {
						
						
						if (v_dest.size() == 9) {
							t = (header->ts).tv_usec;
							
							pair<string, int> first_dest = v_dest[0];
							
							pair<string, pair<string, int> > s_d_pair (sourceIp, first_dest);
							first = tcp_src_dest_time[s_d_pair];
							if(t - first <= 2000000) {
								printf("[%s]: att:%s\n", "Potential network scan", sourceIp);
							}
							for(int i=0; i < 8; i++) {
								v_dest[i] = v_dest[i+1];
							}
							v_dest[8] = cur_dest_port;
							tcp_source_dest[sourceIp] = v_dest;
						} else {
							v_dest.push_back(cur_dest_port);
							tcp_source_dest[sourceIp] = v_dest;	
						}	
					}
				} else { // this is the first time such source send packet
					vector<pair<string, int> > v_dest;
					v_dest.push_back(cur_dest_port);
					
					tcp_source_dest[sourceIp] = v_dest;
					pair<string, pair<string, int> > s_d_pair (sourceIp, cur_dest_port);
					tcp_src_dest_time[s_d_pair] = (header->ts).tv_usec;
				}				
			}
			

		}

		/*-------------------------
		--------------------------- IIS worms
		-------------------------*/		
		
		if (ntohs (ethernetHeader->ether_type) == ETHERTYPE_IP) {
			if(ipHeader->ip_p == IPPROTO_TCP) {
				if(destPort == 80) {
					int tcp_len, ip_len, url_length;
					u_char *url, *tcp_payload;
					char *end_url, *final_url;

					ip_len = (ipHeader->ip_hl & 0xf) * 4;

					tcp_len = (((u_char*)ipHeader)[ip_len + 12] >> 4) * 4;
					tcp_payload = (u_char*)ipHeader + ip_len + tcp_len;


					int offset = 0;
					for(int i=0; i < 8; i++) {
						offset ++;
						if(tcp_payload[i] == ' ') break;
					}
					
					url = tcp_payload + offset;
					char request[8];
					for(int i=0; i<offset-1; i++) {
						request[i] = tcp_payload[i];
					}
					request[offset] = '\0';
					string s(request);
					
					if(s == "GET" || s == "POST" || s == "HEAD" || s == "PUT" || s == "DELETE" || s == "OPTIONS") {
						
						end_url =  strchr(reinterpret_cast<char *>(url), ' ');
						
						url_length = end_url - reinterpret_cast<char *>(url);

						final_url = (char*)malloc(url_length + 1);
						
						for(int i=0; i<url_length; i++) {
							final_url[i] = url[i];
							
						}
						
						string uri(final_url);
						if(uri.find("%255c") != string::npos ||
						uri.find("%25%35%63") != string::npos ||
						uri.find("%252f") != string::npos ||
						uri.find("%%35c") != string::npos ||
						uri.find("%%35%63") != string::npos ||
						uri.find("%C1%1C") != string::npos ||
						uri.find("%C1%9C") != string::npos ||
						uri.find("%c1%9c") != string::npos ||
						uri.find("%c1%af") != string::npos ||
						uri.find("%c1%1c") != string::npos ||
						uri.find("%c1%pc") != string::npos ||
						uri.find("%c1%8s") != string::npos ||
						uri.find("%c0%af") != string::npos ||
						uri.find("%C0%AF") != string::npos ||
						uri.find("%c0%9v") != string::npos ||
						uri.find("%c0%qf") != string::npos ||
						uri.find("%e0%80%af") != string::npos ||
						uri.find("%f0%80%80%af") != string::npos ||
						uri.find("%f8%80%80%80%af") != string::npos ||
						uri.find("%fc%80%80%80%80%af") != string::npos ||
						uri.find("\\%e0\\%80\\%af") != string::npos) {
							printf("[%s]: src:%s, dst:%s\n", "Unicode IIS exploit", sourceIp, destIp);
						} 
					}
				}
			}
		}
		
		/*-------------------------
		--------------------------- NTP reflection DDoS attacks
		-------------------------*/
		
		if(ipHeader->ip_p == IPPROTO_UDP) {
			u_char *request = (u_char *)(data + sizeof(ether_header) + sizeof(ip) + sizeof(udphdr));
			int request_code = (int) request[3];
			if(request_code == 42 && destPort == 123) {
				printf("[%s]: vic:%s, srv:%s\n", "NTP DDoS", sourceIp, destIp);					
			}
		} 
		
    }
	
	cout << "Analyzed " << packetCount << " packets, " << packetSize << " bytes" << endl;
}