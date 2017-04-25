#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "windivert.h"

#define MAXBUF 0xFFFF

int main(int argc, char **argv) {
	HANDLE handle, console;
	UINT i;
	INT16 priority = 0;
	unsigned char packet[MAXBUF];
	UINT packet_len;
	WINDIVERT_ADDRESS addr; // 이 구조체는 캡쳐되거나 삽입된 패킷의 주소를 나타낸다.
	PWINDIVERT_IPHDR ip_header = NULL;
	PWINDIVERT_TCPHDR tcp_header = NULL;

	switch (argc)
	{
	case 2: break;
	case 3: break;
	default:
		fprintf(stderr, "usage : %s windivert-filter [priority]\n", argv[0]);
		fprintf(stderr, "example : \t%s true\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	console = GetStdHandle(STD_OUTPUT_HANDLE);
	handle = WinDivertOpen(argv[1], WINDIVERT_LAYER_NETWORK, priority, WINDIVERT_FLAG_SNIFF);
	if (handle == INVALID_HANDLE_VALUE) {
		// WinDivert 핸들 오류가 발생한 경우
		if (GetLastError() == ERROR_INVALID_PARAMETER) {
			// 유효하지 않은 패킷 필터일 때
			printf("error : filter syntax error\n");
			exit(EXIT_FAILURE);
		}
		printf("error : failed to open the WinDivert device (%d)\n", GetLastError());
		exit(EXIT_FAILURE);
	}

	// 
	if (!WinDivertSetParam(handle, WINDIVERT_PARAM_QUEUE_LEN, 8192)) {
		printf("error : failed to set packet queue length (%d)\n", GetLastError());
		exit(EXIT_FAILURE);
	}

	if (!WinDivertSetParam(handle, WINDIVERT_PARAM_QUEUE_TIME, 2048)) {
		printf("error : failed to set packet queue time (%d)\n", GetLastError());
		exit(EXIT_FAILURE);
	}

	// Main loop :
	while (TRUE) {
		if (!WinDivertRecv(handle, packet, sizeof(packet), &addr, &packet_len)) {
			printf("warning : failed to read packet (%d)\n", GetLastError());
			continue;
		}

		WinDivertHelperParsePacket(packet, packet_len, &ip_header, NULL, NULL, NULL, &tcp_header, NULL, NULL, NULL);
		SetConsoleTextAttribute(console, FOREGROUND_GREEN | FOREGROUND_RED | FOREGROUND_BLUE);


		if (tcp_header != NULL) {
			printf("TCP : [SrcPort = %u DstPort = %u\nSeqNum = %u AckNum = %u\n"
				"HdrLength = %u Reserved1 = %u Reserved2 = %u\nUrg = %u Ack = %u"
				"Psh = %u Rst = %u Syn = %u Fin = %u\nWindow = %u Checksum = 0x%.4X"
				"UrgPtr=%u]\n", ntohs(tcp_header->SrcPort), ntohs(tcp_header->DstPort),
				ntohl(tcp_header->SeqNum), ntohl(tcp_header->AckNum), tcp_header->HdrLength,
				tcp_header->Reserved1, tcp_header->Reserved2, tcp_header->Urg, tcp_header->Ack,
				tcp_header->Psh, tcp_header->Rst, tcp_header->Syn, tcp_header->Fin,
				ntohs(tcp_header->Window), ntohs(tcp_header->Checksum), ntohs(tcp_header->UrgPtr));
		}

		printf("\n\n");

	}
}


