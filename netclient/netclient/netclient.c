#pragma comment (lib, "Ws2_32.lib") 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <WinSock2.h>
#include <Windows.h>
#include <process.h>

#define BUFSIZE 1024
#define PORT 80

int main(int argc, char **argv) {

	WSADATA wsaData;
	struct hostent *hostinfo;
	SOCKET sock; 
	SOCKADDR_IN addr; 
	char buff[BUFSIZE] = { 0, };
	int ip;

	if (argc != 2) {
		printf("Usage : %s [domain name]\n", argv[0]);
		return 1;
	}

	if (WSAStartup(MAKEWORD(2, 0), &wsaData) != 0) {
		printf("WSAStart up Error\n");
		return 1;
	}

	hostinfo = gethostbyname(argv[1]); 
	if (hostinfo == NULL) {
		printf("Not Found Domain Name\n");
		return 1;
	}

	printf("\ndomain : %s\n", hostinfo->h_name);

	for (int i = 0; hostinfo->h_addr_list[i]; i++) {
		printf("IP : %s\n", inet_ntoa(*(IN_ADDR*)hostinfo->h_addr_list[i]));
		ip =  inet_ntoa(*(IN_ADDR*)hostinfo->h_addr_list[0]);
	}
	printf("\n");

	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock == INVALID_SOCKET) return 1;

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET; 
	addr.sin_port = htons(PORT); 
	addr.sin_addr.S_un.S_addr = inet_addr(ip);

	if (connect(sock, (SOCKADDR *)&addr, sizeof(addr)) == SOCKET_ERROR) {
		printf("fail to connect!\n");
		closesocket(sock);
		return 1;
	}

	char webserversend[BUFSIZE] = "GET / HTTP/1.1\r\nConnection: Keep-Alive\r\nHost: ";
	strcat_s(webserversend, sizeof(webserversend), hostinfo->h_name);
	strcat_s(webserversend, sizeof(webserversend), "\r\n\r\n");

	send(sock, webserversend, strlen(webserversend), 0);
	recv(sock, buff, sizeof(buff), 0);
	printf("%s\n", buff);

	WSACleanup();
	closesocket(sock);
	return 0;
}

