#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>	   // ntohs()
#include <sys/unistd.h>		// sleep()
#include <string.h>

#define ARP_REQUEST 1
#define ARP_REPLY 2

typedef struct arpheader arphdr_t;
typedef struct arpPackets arpPackets;

// Arp packet
struct arpheader { 
   u_int16_t htype;    // Hardware Type
   u_int16_t ptype;    // Protocol Type
   u_char hlen;        // Hardware Address Length
   u_char plen;        // Protocol Address Length
   u_int16_t oper;     // Operation Code
   u_char smac[6];     // Source MAC address
   u_char sip[4];      // Source IP address
   u_char dmac[6];     // Destination MAC address
   u_char dip[4];      // Destination IP address
};

struct arpPackets{
   u_char mac[6];			// Packet's source MAC
	char *interface;		// Network interface name of sniffer device
};

void processPackets(u_char *,const struct pcap_pkthdr *,const u_char *);
void setPacket(arphdr_t *);
int equalMac(u_char *,u_char *);
int equalIP(u_char *);

arpPackets arpPacket1, arpPacket2;  // ARP packets going to be sniffed

int main(){
   char *device;							// Device name for sniffing on
   char errMsg[PCAP_ERRBUF_SIZE];	// Error message
   pcap_t *deviceHandle;            // Session handler
   struct bpf_program fp;				// Compiled filter expression
   char filter_exp[] = "arp";       // Filter expression for packets
   bpf_u_int32 mask; 					// Netmask of sniffing device
   bpf_u_int32 net;						// IP address for sniffing device
	struct pcap_pkthdr header;       	
   const u_char *packet;				// Packed sniffed by sniffer
   arphdr_t *arphdr = NULL;
   int i;
   //  Searching for device
   device = pcap_lookupdev(errMsg);
   if(device == 0){
      printf("The following error has occured : %s ",errMsg);
   }
   printf("\nDevice : %s\n",device);
   // Getting IP and netmask for sniffer device
   if(pcap_lookupnet(device,&net,&mask,errMsg) == -1){
      printf("Netmask couldn't be taken for device %s\n",device);
      net = 0;
      mask = 0;
   }
   // Creating a device for sniffing
   deviceHandle = pcap_open_live(device,BUFSIZ,1,0,errMsg);
   if(deviceHandle == 0){
      printf("Device %s couldn't be opened!\n%s\n", device,errMsg);
      return 0;
   }
   // Checking if device header provides required link-layer header 
   if(pcap_datalink(deviceHandle) != DLT_EN10MB){
      printf("Device %s does not provide ethernet headers!",device);
      return 0;
   }
   // Compiles filter expression into filter program
   if(pcap_compile(deviceHandle,&fp,filter_exp,0,net) == -1){
      printf("Couldn't parse filter %s : %s\n",filter_exp,pcap_geterr(deviceHandle));
      return 0;
   }
   // Applying filter
   if(pcap_setfilter(deviceHandle,&fp) == -1){
      printf("Couldn't install filter %s : %s\n",filter_exp,pcap_geterr(deviceHandle));
      return 0;
   }
   // Grabbing a packet
   do{
	   packet = pcap_next(deviceHandle,&header);
	}while(packet == NULL);
	arphdr = (arphdr_t *)(packet + 14);
	// Assigning packet's source MAC to distinguish when we capture second packet.
	{
   	int i;
	   printf("%s ", arphdr->oper == ARP_REQUEST ? "Arp request " : "Arp reply ");
	   printf("Source IP : ") ;
	   for(i = 0; i < 4; i++){
		   printf("%d.",arphdr->sip[i]);
		}
	   printf("\b  MAC : ");
	   for(i = 0; i < 6; i++){
		   arpPacket1.mac[i] = arphdr->smac[i];
		   printf("%02x:",arphdr->smac[i]);
		}
	   printf("\b \n");
   }
	arpPacket2.interface = device;
	while(1){
      pcap_loop(deviceHandle,10,processPackets,NULL);
   }
   pcap_close(deviceHandle);
   return 0;
}

/**
	In this function we are evaluating the packets that we sniffed
	and if it is trying to poison us we notify the user.
*/

void processPackets(u_char *args,const struct pcap_pkthdr *header,const u_char *packet){
	static int count=1;
   int j, offset = 14;
   arphdr_t *arpheader;
	//printf("\nPacket No : %d \n",packetNo);
   if(packet == 0){
      printf("\nSniffing time out !");
      return;
   }
   arpheader = (arphdr_t *)(packet + offset);
   // htype = 1 means ethernet ,ptype = 0x0800 means IPv4
	if(ntohs(arpheader->htype) == 1 && ntohs(arpheader->ptype) == 0x0800){
		setPacket(arpheader);
		if(equalIP(arpheader->dip) == 1){   // Controlling destination of arp packets, evaluate packets those targeted us.
			if(equalMac(arpPacket1.mac,arpPacket2.mac) == 0){	// Packets are coming from different hosts
				count = 1; 
		   	arpPacket1 = arpPacket2;
			}
			else{
		   	count++;
			}
			if(count > 4){
				// notify-send works sometimes buggy somehow.
				//system("pkill notify-osd");
				count = 0;
				system("notify-send -i alert -t 3    'Someone is sniffing your network !'");
				sleep(3);
				system("pkill notify-osd");
				system("notify-send -t 0 -a snoopy  'You are being arp poisoned !\nYour network is not safe !'");
	   		sleep(3);
				system("pkill notify-osd");
				printf("\n\n ARP poisoning attack has discovered !!!\n You are not safe \n!");
				sleep(3);
			}
		}
	}
}

/**
	This function compares two MAC addresses given as parameters
	If they are equal it returs 1 otherwise 0
*/

int equalMac(u_char *mac1, u_char *mac2){
	int i = 0;
	while(i < 6 && mac1[i] == mac2[i]){
		i++;
	}
	if(i == 6){
		return 1;
	}
	return 0;
}

/**
	Assigning packet's IP and MAC address to struct arpPacket 
	where we store distinguishing attributes of packets
*/

void setPacket(arphdr_t *arpheader){
	int j;
	printf("%s", arpheader->oper == ARP_REQUEST ? "Arp Request " : "Arp Reply ");
   printf("Source IP : ");
   for(j = 0;j < 4;j++){
      printf("%d.",arpheader->sip[j]);
	}
	printf("\b  MAC : ");
	for(j = 0;j < 6; j++){
      printf("%02x:",arpheader->smac[j]);
		arpPacket2.mac[j] = arpheader->smac[j];
	}
	printf("\b \n");	
}

/**
	This function gets IP address of host and compare with packet's  destination IP
*/

int equalIP(u_char *pdIP){
	char command[] = "ifconfig  | grep 'inet addr:'| grep -v '127.0.0.1' | cut -d: -f2 | awk '{ print $1}'";  // this script gets the host IP in LAN
   FILE *f = popen(command,"r");   // this will help us to process command line output like a file
	char localIP[16];
	char arpIP[16];
	fscanf(f,"%s",localIP);
	//printf("\n host IP : %s",localIP);
	sprintf(arpIP,"%d.%d.%d.%d",pdIP[0],pdIP[1],pdIP[2],pdIP[3]);
	//printf(" packet IP : %s\n",arpIP);
	pclose(f);
	return !strcmp(localIP,arpIP);
}

