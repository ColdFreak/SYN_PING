#include <stdio.h>
#include <pcap.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#define __FAVOR_BSD
#include <netinet/tcp.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>

#define TH_FIN        0x01
#define TH_SYN        0x02
#define TH_RST        0x04
#define TH_PUSH       0x08
#define TH_ACK        0x10
#define TH_URG        0x20

#define BUFSIZE 4096
char datagram[4096]; /* datagram buffer */
char recvbuf[4096];
char pheader[1024]; /* pseudoheader buffer for computing tcp checksum */

struct sockaddr *sasend;
struct sockaddr *sarecv;
struct sockaddr *lh;


struct addrinfo hints;
struct addrinfo *res;

char local_ip[17];
char remote_ip[17];

int sockfd;
pid_t pid;
socklen_t salen;
unsigned long nsent = 0;
short th_sport = 5555;
short dst_port = 0;
short pig_ack = 0;
short tcp_flags=TH_SYN;


struct sockaddr local;
uint16_t  csum (uint16_t * addr, int len);
void *get_local_ip(struct sockaddr *local);
void readloop(void);
int wait_for_reply(long wait_time);
void syn_send(void);
int recving_time(int sockfd, char *buf, int len, struct sockaddr *sarecv, long timeout);
void proc_v4 (char *ptr, ssize_t len);



uint16_t  csum (uint16_t * addr, int len)
{
  int nleft = len;
  uint32_t sum = 0;
  uint16_t *w = addr;
  uint16_t answer = 0;

  while( nleft > 1 ) {
    sum += *w++;
    nleft -= 2;
  }
  if (nleft == 1) {
    *(unsigned char *)  (&answer) = *(unsigned char *) w;
    sum += answer;
  }
  sum = (sum >> 16)+(sum & 0xffff);
  sum += (sum >> 16);
  answer = ~sum;
  return (answer);
}

void *get_local_ip(struct sockaddr *local) {
/*
 	struct pcap_if {
		struct pcap_if *next;
		char *name;
		char *description;
		pcap_addr *addresses;
		u_int flags;
	};

	struct pcap_addr {
		struct pcap_addr *next;
		struct sockaddr *addr;
		struct sockaddr *netmask;
		struct sockaddr *broadaddr;
		struct sockaddr *dstaddr;
	};
 */
    pcap_if_t *alldevs;
    pcap_if_t *d;
    pcap_addr_t *a;
	char errbuf[PCAP_ERRBUF_SIZE];
    int status = pcap_findalldevs(&alldevs, errbuf);
    if(status != 0) {
	printf("%s\n",errbuf);
	return NULL;
    }
    for(d = alldevs; d != NULL; d= d->next) {
	for(a = d->addresses; a!= NULL; a = a->next) {
		if(a->addr->sa_family == AF_INET)  {
			memcpy(local, a->addr, sizeof(struct sockaddr));
			return;
		}
	}
    }
}

void readloop(void) {
	ssize_t n;
	int size;

	// create socket from here
	if(res->ai_family == AF_INET) {
		if((sockfd = socket(AF_INET,SOCK_RAW,IPPROTO_TCP)) < 0) {
			perror("socket");
			exit(1);
		}
	}
	else {
		fprintf(stderr,"unknown address family %d", res->ai_family);
		exit (1);
	}
	setuid(getuid());

	size = 60 * 1024;
	setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
	int one = 1;
	const int *val = &one;
	if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
		fprintf(stderr, "Warning: Cannot set HDRINCL for port 0");

    	while(nsent < 3) {
        	syn_send();
        	wait_for_reply(1000);
    	}
}

int wait_for_reply(long wait_time) {
	/*timeout or not */
	int result;
	ssize_t n;
    //
	result = recving_time(sockfd,recvbuf,sizeof(recvbuf),sarecv, wait_time);

	if(result < 0)
		return 0;
	n = sizeof(recvbuf);
	proc_v4(recvbuf, n);
	return 1;
}

int recving_time(int sockfd, char *buf, int len, struct sockaddr *sarecv, long timeout) {
	char recived_ip[20];
	ssize_t n;
	char controlbuf[BUFSIZE];
	struct msghdr msg;
	struct iovec iov;

	struct timeval to;
	int readable;
	fd_set readset;

select_again:
	if(timeout < 1000) {
		to.tv_sec = 0;
		to.tv_usec = timeout;
	}
	else {
		to.tv_sec = timeout / 1000;
		to.tv_usec = timeout % 1000;
	}

	FD_ZERO(&readset);
	FD_SET(sockfd, &readset);
	readable = select(sockfd+1, &readset, NULL, NULL, &to);
	if(readable < 0) {
		if(errno == EINTR)
			goto select_again;
		else {
			perror("select() error");
			exit(1);
		}
	}

	if(readable == 0)  {
		return -1;
	}

	iov.iov_base = recvbuf;
	iov.iov_len = sizeof(recvbuf);
	msg.msg_name = sarecv;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = controlbuf;

	for(;;) {
		n = recvmsg(sockfd, &msg,0);
		fprintf(stderr, "recived %d bytes. ", n);
//		fprintf(stderr, "From %s,recived %d bytes. ",inet_ntop(AF_INET,&(((struct sockaddr_in*)sarecv)->sin_addr),recived_ip,128), n);

		if( n < 0)
			if(errno == EINTR )
				continue;
			else {
				perror("recvmsg");
				exit(1);
			}
		else
			break;
	}
	return n;
}

void syn_send(void) {
	struct ip *iph = (struct ip *) datagram;
	struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct ip));
	struct sockaddr_in servaddr;
	memset(datagram, 0, 4096); /* zero out the buffer */

	iph->ip_hl = 5;
	iph->ip_v = 4;
	iph->ip_tos = 0;
	iph->ip_len = sizeof (struct ip) + sizeof (struct tcphdr) + 8 + 6 + 6 ; /* data size = 0, but tcp using option flags */
	iph->ip_id = htons (pid);
	iph->ip_off = 0;
	iph->ip_ttl = 250;
	iph->ip_p = 6;
	iph->ip_sum = 0;
	iph->ip_src.s_addr = ((struct sockaddr_in*)lh)->sin_addr.s_addr;
	iph->ip_dst.s_addr = ((struct sockaddr_in*)sasend)->sin_addr.s_addr;
	//OLD WAY iph->ip_src.s_addr = inet_addr (src_ip);/* source ip  */
	//inet_pton(AF_INET, src_ip, &(iph->ip_src));
	//iph->ip_dst.s_addr = servaddr.sin_addr.s_addr;

	tcph->th_sport = htons (++th_sport); /* source port */
	tcph->th_dport = htons (dst_port); /* destination port */
	tcph->th_seq = htonl(nsent);
	tcph->th_ack = htonl(pig_ack);/* in first SYN packet, ACK is not present */
	tcph->th_x2 = 0;
	// tcph->th_off = sizeof(struct tcphdr)/4; /* data position in the packet */
	// Special chirico adjustment to give 2x32
	tcph->th_off = 7+2+1 ;

	int tcphdr_size = sizeof(struct tcphdr);

//	fprintf(stderr,"Data offset %d  sizeof(struct tcphdr)=%d\n",tcph->th_off,sizeof(struct tcphdr));

	tcph->th_flags = tcp_flags; /* initial connection request */
	tcph->th_win = htons (57344); /* FreeBSD uses this value too */
	tcph->th_sum = 0; /* we will compute it later */
	tcph->th_urp = 0;

	tcphdr_size=40;

	memset(pheader,0x0,sizeof(pheader));
	memcpy(&pheader,&(iph->ip_src.s_addr),4);
	memcpy(&pheader[4],&(iph->ip_dst.s_addr),4);
	pheader[8]=0; // just to underline this zero byte specified by rfc
	pheader[9]=(u_int16_t)iph->ip_p;
	pheader[10]=(u_int16_t)(tcphdr_size & 0xFF00)>>8;
	pheader[11]=(u_int16_t)(tcphdr_size & 0x00FF);


	memcpy(&pheader[12], tcph, sizeof(struct tcphdr));

	tcph->th_sum = csum ((uint16_t *) (pheader),tcphdr_size+12);
  	iph->ip_sum = csum ((unsigned short *) datagram, iph->ip_len >> 1);

	sasend = res->ai_addr;
	salen = res->ai_addrlen;
	if (sendto (sockfd,datagram,iph->ip_len ,0,sasend, salen) < 0) {
        	fprintf(stderr,"Error in sendto\n");
        	exit(1);
    }
	nsent++;
}

int main(int argc, char **argv) {
	int n; /* getaddrinfo return value */
	char *host;



	if(argc != 2) {
		perror("usage: ./ping <hostname>");
		exit (1);
	}
	/*
	 	struct sockaddr {
			unsigned short sa_family;
			char sa_data[14];
		}
	 */
	get_local_ip(&local);
	lh = &local;

	host = argv[1];
	pid = getpid() & 0xffff;

	bzero(&hints, sizeof(struct addrinfo));
	hints.ai_flags = AI_CANONNAME;
	if( ( n = getaddrinfo(host, NULL, &hints, &res)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n",gai_strerror(n));
		exit (1);
	}

	sasend = res->ai_addr;
	switch (sasend->sa_family) {
		case AF_INET:
			if(inet_ntop(AF_INET,&(((struct sockaddr_in*)sasend)->sin_addr), remote_ip, 128) == NULL) {
				perror("inet_ntop");
				exit (1);
			}
			break;

		default:
			perror("Not IPv4 address");
			exit (1);
	}

	readloop();
	return 0;

}

void proc_v4 (char *ptr, ssize_t len) {
	int ip_size, tcp_size;
	struct ip *ip;
	struct tcphdr *tcp;

	ip = (struct ip*)ptr;
	/* only check two fields of ip header, length and protocol */
	//ip_size = ntohs(ip->ip_len) * 4; /* length of ip header */
/*	fprintf(stderr, "ip_len = %d\n",ntohs(ip->ip_len));
	if(ip_size < 20) {
		fprintf(stderr, "Invalid IP header length: %d\n",ip_size);
		return ;
	} */

	ip_size = ip->ip_hl << 2;
	fprintf(stderr, "ip header is %d bytes. ",ip_size);
	if(ip_size < 20) {
		fprintf(stderr, "Invalid IP packet\n");
		return ;
	}
	printf("ip protocol = %d, it's a valid packet; ", ip->ip_p);

	if(ip->ip_p != IPPROTO_TCP ) {

		fprintf(stderr,"Returned Packet is not TCP protocol\n");
		return;		/*second, check protocol */
	}

	tcp = (struct tcphdr *)(ptr + sizeof(struct ip)); /* start of icmp header */
	tcp_size = tcp->th_off << 2;
	fprintf(stderr, "TCP header is %d bytes, ",tcp_size);
	if(tcp_size < 20) {
		fprintf(stderr, "Invalid TCP packet\n");
		return ;
	}


	if(((tcp->th_flags & 0x04) == TH_RST ) && (tcp->th_flags & 0x10) == TH_ACK)
		fprintf(stdout, "Host on line.\n");

	if(((tcp->th_flags & 0x02) == TH_SYN) && (tcp->th_flags & 0x10) == TH_ACK)
		fprintf(stdout, "TCP port open\n");
}
