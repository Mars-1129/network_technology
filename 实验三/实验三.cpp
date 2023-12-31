#ifndef  HAVE_REMOTE
#define HAVE_REMOTE
#endif
#include <algorithm>
#include<string>
#include<Winsock2.h>
#include "pcap.h"
#include <iostream>
#include <vector>

#define _CRT_SECURE_NO_WARNINGS



typedef struct FrameHeader_t {	//帧首部
	BYTE	DesMAC[6];	// 目的地址
	BYTE 	SrcMAC[6];	// 源地址
	WORD	FrameType;	// 帧类型
} FrameHeader_t;
#define SENDDEVICE "Network adapter 'MediaTek Wi-Fi 6 MT7921 Wireless LAN Card' on local host"
#pragma pack(1)

typedef struct ARPFrame_t {
	FrameHeader_t Frameheader;
	WORD HardwareType;
	WORD ProtocolType;
	BYTE HLen;
	BYTE PLen;
	WORD Operation;
	BYTE SendHa[6];
	DWORD SendIP;
	BYTE RecvHa[6];
	DWORD RecvIP;
}ARPFrame_t;
#pragma pack()

struct dev
{
	char* name;
	std::string descrip;
	std::string addr;
	std::string netmask;
	std::string broadaddr;

};
std::vector<dev> devices;

std::string hostMac = " CC-6B-1E-8C-F1-13";  // 本机的MAC地址
ARPFrame_t* ARPProtocal;

uint32_t netMask; // 选定设备的子网掩码
unsigned char* ipMac = new unsigned char[6]; //本机MAC
time_t start, now;//计时
long float time_sum;
int nicId;


int nicFind();  // 从设备列表中筛选出无线网卡



void output()
{
	for (std::vector<dev>::iterator it = devices.begin(); it != devices.end(); it++)
	{
		std::cout << it->name << std::endl
			<< "description:" << it->descrip << std::endl
			<< "IPaddr:" << it->addr << std::endl
			<< "netmask:" << it->netmask << std::endl;
		std::cout << std::endl;
	}
	std::cout << "The numbers of NIC: " << devices.size() << std::endl;
}

void output(int id)
{
	std::cout << devices[id].name << std::endl
		<< "description:" << devices[id].descrip << std::endl
		<< "IPaddr:" << devices[id].addr << std::endl
		<< "netmask:" << devices[id].netmask << std::endl;
	std::cout << std::endl;
}

void getAllDev()
{
	pcap_if_t* alldevs;
	pcap_if_t* d;
	pcap_addr_t* a;
	char errbuf[PCAP_ERRBUF_SIZE]; // 宏定义给定长度
	struct in_addr net_mask_address;
	struct in_addr net_ip_address;

	uint32_t net_ip;
	uint32_t net_mask;

	// 获取本机的设备列表
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING,
		NULL,
		&alldevs,
		errbuf
	) == -1)
	{
		std::cout << "ERROR";
		pcap_freealldevs(alldevs);
		return;
	}
	for (d = alldevs; d != NULL; d = d->next)
	{
		dev temp;
		temp.name = d->name;
		temp.descrip = d->description;
		pcap_lookupnet(d->name, &net_ip, &net_mask, errbuf); // 获取掩码以及IP地址
		net_ip_address.s_addr = net_ip;
		net_mask_address.s_addr = net_mask;

		for (a = d->addresses; a != NULL; a = a->next) {
			if (a->addr->sa_family == AF_INET)  // 判读地址是否为IP地址
			{

				inet_ntop(AF_INET, &net_ip_address, &temp.addr[0], INET_ADDRSTRLEN);
				inet_ntop(AF_INET, &net_mask_address, &temp.netmask[0], INET_ADDRSTRLEN);
				if (temp.descrip == SENDDEVICE)
					netMask = net_mask;  // 获得需要设备的掩码

				devices.push_back(temp);


			}
		}
	}

	pcap_freealldevs(alldevs);
}


u_long ipTrans(std::string in)
{
	char ipaddr[100];
	strcpy_s(ipaddr, sizeof(ipaddr), in.c_str());
	DWORD num[4];
	sscanf_s(ipaddr, "%u.%u.%u.%u", &num[0], &num[1], &num[2], &num[3]);
	num[0] = num[0] << 24;
	num[1] = num[1] << 16;
	num[2] = num[2] << 8;
	u_long temp = num[0] + num[1] + num[2] + num[3];
	return htonl(temp);

}
std::string transIp(DWORD in)//对应的IP地址
{
	std::string ans;
	DWORD mask[] = { 0xFF000000,0x00FF0000,0x0000FF00,0x000000FF };
	DWORD num[4];

	num[0] = in & mask[0];
	num[0] = num[0] >> 24;
	num[1] = in & mask[1];
	num[1] = num[1] >> 16;
	num[2] = in & mask[2];
	num[2] = num[2] >> 8;
	num[3] = in & mask[3];

	char temp[100];
	sprintf_s(temp, "%d.%d.%d.%d", num[0], num[1], num[2], num[3]);
	ans = temp;
	return ans;
}
std::string transMac(BYTE* MAC)//目的地址与源地址
{
	std::string ans;
	char temp[100];
	sprintf_s(temp, "%02X-%02X-%02X-%02X-%02X-%02X", int(MAC[0]), int(MAC[1]), int(MAC[2]), int(MAC[3]), int(MAC[4]), int(MAC[5]));
	ans = temp;
	return ans;
}

BYTE* macTrans(std::string in)
{
	char temp[100];
	strcpy_s(temp, sizeof(temp), in.c_str());
	unsigned char* MAC = new unsigned char[6];
	sscanf_s(temp, "%02X-%02X-%02X-%02X-%02X-%02X", &MAC[0], &MAC[1], &MAC[2], &MAC[3], &MAC[4], &MAC[5]);
	return MAC;

}

int nicFind()  // 从设备列表中筛选出无线网卡
{
	for (int i = 0; i < devices.size(); i++)
	{
		if (devices[i].descrip == SENDDEVICE)
			return i;
	}
}




void initializeARPFrame(ARPFrame_t* ARPFrame, const std::string& srcMac, const std::string& srcIp, const std::string& destIp) {
	// 初始化 ARP 帧
	memset(ARPFrame, 0, sizeof(ARPFrame_t));
	memcpy(ARPFrame->Frameheader.SrcMAC, macTrans(srcMac), 6);
	memset(ARPFrame->Frameheader.DesMAC, 0xff, 6);
	ARPFrame->Frameheader.FrameType = htons(0x0806);
	ARPFrame->ProtocolType = htons(0x0800);
	ARPFrame->HLen = 6;
	ARPFrame->PLen = 4;
	ARPFrame->Operation = htons(0x0001);
	memcpy(ARPFrame->SendHa, macTrans(srcMac), 6);
	ARPFrame->SendIP = ipTrans(srcIp);
	memset(ARPFrame->RecvHa, 0, 6);
	ARPFrame->RecvIP = ipTrans(destIp);
}

void sendARP(const std::string& destIp, const std::string& srcIp, const std::string& srcMac) {
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* adapter;
	ARPFrame_t* ARPFrame = new ARPFrame_t;

	// 初始化 ARP 帧
	initializeARPFrame(ARPFrame, srcMac, srcIp, destIp);

	// 打开网络适配器
	if ((adapter = pcap_open(devices[nicId].name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 6000, NULL, errbuf)) == NULL) {
		// 错误处理
		delete ARPFrame;
		return;
	}

	// 发送 ARP 包
	if (pcap_sendpacket(adapter, reinterpret_cast<unsigned char*>(ARPFrame), sizeof(ARPFrame_t)) != 0) {
		// 错误处理
	}

	// 释放资源
	delete ARPFrame;
	pcap_close(adapter);
}

void capturePacket() {
	char errbuf[PCAP_ERRBUF_SIZE]; // 定义缓冲区大小的宏
	int res;
	pcap_t* adapter; // pcap_open 返回值
	pcap_pkthdr* pkt_header;
	const u_char* pkt_data = new u_char;
	struct bpf_program fcode; // 存储编译后的过滤代码
	ULONG SourceIP, DestinationIP;

	if (devices.empty()) {
		std::cout << "找不到设备！" << std::endl;
		return;
	}

	output(nicId);

	// 打开捕获适配器
	if ((adapter = pcap_open(devices[nicId].name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 3000, NULL, errbuf)) == NULL) {
		return;
	}

	// 编译 ARP 数据包的过滤代码
	if (pcap_compile(adapter, &fcode, "arp", 1, netMask) < 0) {
		return;
	}

	// 设置编译后的过滤代码
	if (pcap_setfilter(adapter, &fcode) < 0) {
		return;
	}

	start = time(NULL);

	// 捕获循环
	while ((res = pcap_next_ex(adapter, &pkt_header, &pkt_data)) >= 0) {
		now = time(NULL);

		// 检查是否已经过去了 25 秒
		if ((time_sum = difftime(now, start)) > 25) {
			break;
		}

		// 如果没有可用数据包，继续等待
		if (res == 0) {
			printf("等待：%f 秒\n", time_sum);
			continue;
		}

		ARPProtocal = (ARPFrame_t*)(pkt_data);

		// 检查是否是 ARP 数据包
		if (ARPProtocal->Frameheader.FrameType == htons(0x0806)) {
			if (ARPProtocal->Operation == htons(0x0002)) {
				std::cout << "回复源 MAC 地址: " << transMac(ARPProtocal->SendHa) << std::endl;
				std::cout << "回复目标 MAC 地址: " << transMac(ARPProtocal->RecvHa) << std::endl;
			}
			else if (ARPProtocal->Operation == htons(0x0001)) {
				std::cout << "请求源 MAC 地址: " << transMac(ARPProtocal->SendHa) << std::endl;
				std::cout << "请求目标 MAC 地址: " << transMac(ARPProtocal->RecvHa) << std::endl;
				std::cout << "请求源 IP 地址: " << transIp(ARPProtocal->SendIP) << std::endl;
			}

			continue;
		}
	}
	delete[] pkt_data;
}

int main()
{


	getAllDev();
	output();

	std::cin >> nicId;


	sendARP(devices[nicId].addr, "112.112.112.112", "66-66-66-66-66-66"); // 首先由虚拟地址向本机IP发送数据包，获取本机MAC
	std::string dstip;
	std::cin >> dstip;

	//sendARP(dstip, devices[nicId].addr, hostMac);
	capturePacket();

}
