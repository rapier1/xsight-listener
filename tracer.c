
/*
 * Copyright (c) 2015 The Board of Trustees of Carnegie Mellon University.
 *
 *  Author: Chris Rapier <rapier@psc.edu>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the MIT License.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the MIT License for more details.
 *
 * You should have received a copy of the MIT License along with this library;
 * if not, see http://opensource.org/licenses/MIT.
 *
 */ 

#include "tracer.h"

int trace4(char *dest, char *src, char ips[30][45]) {
	int max_ttl=30; /* TODO: might want to make this a configurable value. -BDL */
	u_short sport=0; /* use ephemeral */
	u_short dport=33434;
	const char *message = "xsighting for all";
	int packetsize,  sockfd, icmp_sock, ttl;
	socklen_t fromlen = 0;
	int number = 0;
	
	struct icmphdr *icmp;
	char recvbuf[BUFFER_SIZE] = "\0";
	char packet[BUFFER_SIZE] = "\0";
	char ipstr[INET_ADDRSTRLEN] = "\0";

	int ret = 0;
	struct addrinfo hint;
	struct addrinfo *destres = 0;
	struct sockaddr_in *destaddr;
	struct sockaddr_in srcaddr;
	fd_set readfds;
	struct timeval timeout;

	memset(&hint, '\0', sizeof hint);
	hint.ai_family = AF_INET;
	hint.ai_socktype = SOCK_DGRAM;
	hint.ai_flags = hint.ai_flags | AI_CANONNAME;

	ret = getaddrinfo(dest, NULL, &hint, &destres);
	if (ret != 0)
		perror ("getaddrinfo:");

	destaddr = (struct sockaddr_in*)destres->ai_addr;
	destaddr->sin_port = htons(dport);

	memset(&srcaddr, '\0', sizeof(srcaddr));
	srcaddr.sin_family = AF_INET;
	srcaddr.sin_port = htons(sport);
	inet_pton(AF_INET, src, &srcaddr.sin_addr); 

	if ((icmp_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
		perror("icmp socket:");
		exit(1);
	}

	if((sockfd=socket(AF_INET,SOCK_DGRAM, 0))<0) {
		perror("socket");
		exit(1);
	}

	ret = bind(sockfd, (struct sockaddr *)&srcaddr, sizeof(srcaddr));	
	if (ret < 0) {
		perror ("Failed to bind to IP");
		exit(1);
	}
	strncpy(packet, message, strlen(message));
	packetsize = strlen(packet);

	FD_ZERO(&readfds);
	FD_SET(icmp_sock, &readfds);
       	for (ttl=1; ttl < max_ttl; ttl++)
	{
		timeout.tv_sec = 1;
		timeout.tv_usec = 0;
		
		setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));		

		if(sendto(sockfd,packet,packetsize,0,(struct sockaddr *)destaddr,
			  sizeof(*destaddr)) != packetsize){ 
			perror("sendto");
			exit(1);
		}
		ret = select(icmp_sock+1, &readfds, NULL, NULL, &timeout);
		if (ret == -1) {
			perror ("Select v4:");
		} else if (ret) {
			number = recvfrom(icmp_sock, recvbuf, BUFFER_SIZE-1, 0, 
				  (struct sockaddr *)&srcaddr, &fromlen);
			/* make sure the string is null terminated */
			recvbuf[number] = '\0';
			icmp = (struct icmphdr *)(recvbuf+sizeof(struct iphdr));
			inet_ntop(AF_INET, &srcaddr.sin_addr.s_addr, ipstr, sizeof(ipstr));
			strncpy(ips[ttl], ipstr, strlen(ipstr));
			ips[ttl][strlen(ipstr)] = '\0';
		} else {
			/* if ret is 0 the sock is removed from the FD_SET*/
			FD_SET(icmp_sock, &readfds);
			strncpy(ips[ttl], "*\0", 2);
			continue;
		}
		if(icmp->type==ICMP_TIME_EXCEEDED && icmp->code==ICMP_EXC_TTL)
			continue;
		if(icmp->type==ICMP_DEST_UNREACH && icmp->code==ICMP_PORT_UNREACH)
			break;
	}
	close(icmp_sock);
	close(sockfd);
	freeaddrinfo(destres);
	return(ttl);
}

int trace6(char *dest, char *src, char ips[30][45]) {
	int max_ttl=30;
	u_short sport = 0; /* use ephemeral */
	u_short dport=33434;
	const char *message = "xsighting for all";
	int packetsize,  sockfd,  icmp_sock, ttl;
	int number = 0;

	struct icmphdr *icmp;
	char recvbuf[1500] = "\0";
	char packet[1500] = "\0";
	char dipstr[INET6_ADDRSTRLEN] = "\0";

	int ret = 0;
	int on = 2;
	struct addrinfo hint;
	struct addrinfo *destres = 0;
	struct sockaddr_in6 *destaddr;
	struct sockaddr_in6 srcaddr;
	socklen_t fromlen = 0;
	fd_set readfds;
	struct timeval timeout;

	memset(&hint, '\0', sizeof(hint));
	hint.ai_family = AF_INET6;

	memset(&srcaddr, '\0', sizeof(srcaddr));
	srcaddr.sin6_port = htons(sport);
	srcaddr.sin6_family = AF_INET6;
	inet_pton(AF_INET6, src, &srcaddr.sin6_addr);

	ret = getaddrinfo(dest, NULL, &hint, &destres);
	destaddr = (struct sockaddr_in6*)destres->ai_addr;
	destaddr->sin6_family = AF_INET6;
	destaddr->sin6_port=htons(dport);

	icmp_sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
	setsockopt(icmp_sock, SOL_RAW, IPV6_CHECKSUM, &on, sizeof(on));

	if((sockfd=socket(AF_INET6,SOCK_DGRAM, 0))<0) {
		perror("socket");
		exit(1);
	}
	
	ret = bind(sockfd, (struct sockaddr *)&srcaddr, sizeof(srcaddr));	
	if (ret < 0) {
		perror ("Failed to bind to IP");
		exit(1);
	}

	FD_ZERO(&readfds);
	FD_SET(icmp_sock, &readfds);
	timeout.tv_sec = 1;
	timeout.tv_usec = 0;

	strncpy(packet, message, strlen(message));
	packetsize = strlen(packet);

       	for (ttl=1; ttl <=max_ttl; ttl++) {
		timeout.tv_sec = 1;
		timeout.tv_usec = 0;

		setsockopt(sockfd, SOL_IPV6, IPV6_UNICAST_HOPS, &ttl, sizeof(ttl));

		if(sendto(sockfd, packet, packetsize, 0, (struct sockaddr *)destaddr, 
			  sizeof(*destaddr)) != packetsize){ 
			perror("sendto");
			exit(1);
		}
		ret = select(icmp_sock+1, &readfds, NULL, NULL, &timeout);
		if (ret == -1) {
			perror ("Select v6:");
		} else if (ret) {
			number = recvfrom(icmp_sock, recvbuf, BUFFER_SIZE-1, 0, 
				  (struct sockaddr*)&srcaddr, &fromlen);
			/* make sure the string is null terminated */
			recvbuf[number] = '\0';
			icmp = (struct icmphdr *)recvbuf;
			
			inet_ntop(AF_INET6, &srcaddr.sin6_addr, dipstr, sizeof(dipstr));
			strncpy(ips[ttl], dipstr, strlen(dipstr));
			ips[ttl][strlen(dipstr)] = '\0';
		} else {
			/* if ret is 0 the sock is removed from the FD_SET*/
			FD_SET(icmp_sock, &readfds);
			strncpy(ips[ttl], "*\0", 2);
			continue;
		}

		if(icmp->type==ICMPV6_TIME_EXCEED && icmp->code== ICMPV6_EXC_HOPLIMIT)
			continue;
		if(icmp->type==ICMPV6_DEST_UNREACH && icmp->code==ICMPV6_PORT_UNREACH)
			break;
	}
	close(icmp_sock);
	close(sockfd);
	freeaddrinfo(destres);
	return (ttl);
}
