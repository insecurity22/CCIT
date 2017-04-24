#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "windivert.h"
#define MAXBUF 0xFFFF

void main(int argc, char *argv) {

	HANDLE handle, console;
	UINT i;
	INT16 priority = 0;
	unsigned char packet[MAXBUF];
	UINT packet_len;
	WINDIVERT_ADDRESS addr;     
	PWINDIVERT_IPHDR ip_header;
	PWINDIVERT_TCPHDR tcp_header;


	priority = (INT16)atoi(argv[2]);
	console = GetStdHandle(STD_OUTPUT_HANDLE); //


	// �־��� ���Ϳ� ���� WinDivert �ڵ� ����
	handle = WinDivertOpen(argv[1], WINDIVERT_LAYER_NETWORK, priority, WINDIVERT_FLAG_SNIFF);
	if (handle == INVALID_HANDLE_VALUE) {
		if (GETLastError() == ERROR_INVALID_PARAMETER) { // ��ȿ���� ���� ������ ��
			printf("filter syntax error \n");
			exit(EXIT_FAILURE);
		}
		printf("error : failed to open the WinDivert device \n");
		exit(EXIT_FAILURE);
	}


	if (!WinDivertSetParam(handle, WINDIVERT_PARAM_QUEUE_LEN, 8192)) {
		// ���ڰ� : WinDivertOpen�� ���� ������ ��ȿ�� �ڵ�, WinDivert �Ű� ���� �̸�, �Ű� ������ �� ��
		// ��Ŷ ��⿭�� �ִ� ���� ����
		printf("error : failed to set packet queue langth \n");
		exit(EXIT_FAILURE);
	}

	// ��Ŷ�� �ڵ����� �����Ǳ� ���� ����� �� �ִ� �ּ� �ð� ����
	if (!WinDivertSetParam(handle, WINDIVERT_PARAM_QUEUE_TIME, 2048)) {
		printf("error : failed to set packet queue time \n");
		exit(EXIT_FAILURE);
	}



	// Main Loop :
	while (1){


		// Read a matching packet
		if (!WinDivertRecv(handle, packet, sizeof(packet), &addr, &packet_len)) {
			printf("Warning : failed to read packet \n");
			continue;
		}	

		
		if (tcp_header != NULL) {
			SetConsoleTextAttribute(console, FOREGROUND_GREEN);
			printf("TCP [SrcPort=%u DstPort=%u SeqNum=%u AckNum=%u"
				"HdrLength=%u Reserved1=%u Reserved2=%u Urg=%u Ack=%u"
				"Psh=%u Rst=%u Syn=%u Fin=%u Window=%u Checksum=0x%.4X UrgPtr=%u] \n",
				ntohs(tcp_header->SrcPort), ntohs(tcp_header->DstPort),
				ntohl(tcp_header->SeqNum), ntohl(tcp_header->AckNum),
				tcp_header->HdrLength, tcp_header->Reserved1,
				tcp_header->Reserved2, tcp_header->Urg, tcp_header->Ack,
				tcp_header->Psh, tcp_header->Rst, tcp_header->Syn,
				tcp_header->Fin, ntohs(tcp_header->Window),
				ntohs(tcp_header->Checksum), ntohs(tcp_header->UrgPtr));
		}
	}


}