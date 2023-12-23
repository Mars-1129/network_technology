#include "k.h"
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#define ETH_IP 0x0800
#define ARP_REQUEST 1
#define ARP_REPLY 2
#define MAX_WORK_TIME 2000
#define HAVE_REMOTE
#define ETH_ARP 0x0806
#define ARP_HARDWARE 1



#pragma warning(disable:4996)

char** myip = (char**)malloc(sizeof(char*) * 2);
char** mynetmask = (char**)malloc(sizeof(char*) * 2);
char** mynet = (char**)malloc(sizeof(char*) * 2);

BYTE mymac[2][6];
BYTE broadcastmac[6];
pcap_if_t* alldevs;
pcap_t* adhandle;
pcap_addr_t myaddr[2];

void iptostr(u_long addr, char* str)
{
	static char str1[3 * 4 + 3 + 1];//3 bytes of numbers and 3 dots and a '\0'
	u_char* p = (u_char*)&addr;
	sprintf_s(str1, "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	memcpy(str, str1, 16);
	return;
}

//路由表项
class RouteTableItem {
public:
	DWORD netmask; //子网掩码
	DWORD dstnet; //目标网络地址
	DWORD nextip; //下一跳IP地址
	int type; //类型，0为直接连接，1为用户添加
	RouteTableItem* nextitem; //指向下一个路由表项的指针，采用链表形式存储
	RouteTableItem() {
		memset(this, 0, sizeof(*this)); //初始化路由表项的成员变量为0
	}
	RouteTableItem(DWORD netmask, DWORD dstnet, int type, DWORD nextip = 0) {
		this->netmask = netmask; //设置子网掩码
		this->dstnet = dstnet; //设置目标网络地址
		this->nextip = nextip; //设置下一跳IP地址，默认为0
		this->type = type; //设置类型，默认为0
	}
	void print() {
		char* str = (char*)malloc(sizeof(char) * 16); //分配内存空间用于存储IP地址字符串
		iptostr(netmask, str); //将子网掩码转换为字符串
		printf("Netmask: %s\n", str); //输出子网掩码
		iptostr(dstnet, str); //将目标网络地址转换为字符串
		printf("Destination: %s\n", str); //输出目标网络地址
		iptostr(nextip, str); //将下一跳IP地址转换为字符串
		printf("Next ip: %s\n", str); //输出下一跳IP地址
		printf("Type: %d\n", type); //输出类型
	}
};

//路由表
class RouteTable {
public:
	RouteTableItem* head; // 头指针
	RouteTableItem* tail; // 尾指针
	int num; // 路由表中的项数

	RouteTable() {
		DWORD netmask = inet_addr(mynetmask[0]); // 将网络掩码转换为32位整数
		DWORD dstnet = (inet_addr(myip[0])) & (inet_addr(mynetmask[0])); // 计算目标网络地址
		int type = 0; // 类型为0表示直接发送
		head = new RouteTableItem(netmask, dstnet, type); // 创建头节点
		tail = new RouteTableItem; // 创建空尾节点
		head->nextitem = tail; // 头节点指向尾节点

		RouteTableItem* tmp = new RouteTableItem; // 创建临时节点用于添加新的路由表项
		tmp->dstnet = (inet_addr(myip[1])) & (inet_addr(mynetmask[1])); // 计算第二个目标网络地址
		tmp->netmask = inet_addr(mynetmask[1]); // 设置网络掩码
		tmp->type = 0; // 类型为0表示直接发送
		//tmp->nextip = (inet_addr(myip[1])); // 暂时不设置下一跳IP地址
		add(tmp); // 添加新的路由表项
		num = 2; // 路由表中有2个IP地址
	}

	// 添加表项（直接投递在最前，前缀长的在前面）
	void add(RouteTableItem* newitem) {
		num++; // 增加路由表中的项数
		// 如果新项的类型为0，则直接添加到头节点之后
		if (newitem->type == 0) {
			newitem->nextitem = head->nextitem;
			head->nextitem = newitem;
			return;
		}
		// 如果新项的类型不为0，则根据网络掩码的长度进行排序
		RouteTableItem* cur = head;
		while (cur->nextitem != tail) {
			if (cur->nextitem->type != 0 && cur->nextitem->netmask < newitem->netmask) {
				break;
			}
			cur = cur->nextitem;
		}
		// 将新项插入到当前节点和下一个节点之间
		newitem->nextitem = cur->nextitem;
		cur->nextitem = newitem;
	}

	// 删除表项
	void remove(int index) {
		if (index >= num) { // 如果索引超出范围，则打印错误信息并返回
			printf("路由表项%d超过范围！\n", index);
			return;
		}
		if (index == 0) { // 如果索引为0，则删除头节点
			if (head->type == 0) {
				printf("该路由表项不可删除！\n");
			}
			else {
				head = head->nextitem;
			}
			return;
		}
		RouteTableItem* cur = head;
		int i = 0;
		while (i < index - 1 && cur->nextitem != tail) { // 找到要删除的节点的前一个节点
			i++;
			cur = cur->nextitem;
		}
		if (cur->nextitem->type == 0) { // 如果要删除的节点类型为0，则打印错误信息并返回
			printf("该路由表项不可删除！\n");
		}
		else {
			cur->nextitem = cur->nextitem->nextitem; // 否则，将要删除的节点从链表中移除
		}
	}

	// 打印路由表
	void print() {
		printf("Route Table:\n");
		RouteTableItem* cur = head;
		int i = 1;
		while (cur != tail) {
			printf("No.%d:\n", i);
			cur->print(); // 调用每个节点的print方法进行打印
			cur = cur->nextitem;
			i++;
		}
	}

	// 查找，最长前缀，返回下一跳的ip
	DWORD lookup(DWORD dstip) {
		DWORD res;
		RouteTableItem* cur = head;
		while (cur != tail) {
			res = dstip & cur->netmask; // 计算目标IP地址与当前节点的网络掩码的按位与结果
			if (res == cur->dstnet) { // 如果结果等于当前节点的目标网络地址，则表示找到了最长前缀
				if (cur->type != 0) { // 如果当前节点的类型不为0，则表示需要转发，返回下一跳IP地址
					return cur->nextip;
				}
				else { // 如果当前节点的类型为0，则表示可以直接发送，返回0
					return 0;
				}
			}
			cur = cur->nextitem; // 继续查找下一个节点
		}
		printf("没有找到对应的路由表项！\n"); // 如果遍历完所有节点都没有找到匹配的项，则打印错误信息并返回-1
		return -1;
	}
};

class ARPTableItem {
public:
	// IP地址，使用DWORD类型表示
	DWORD IP;
	// MAC地址，使用BYTE数组表示，长度为6
	BYTE MAC[6];
	// 静态变量，用于记录ARP表中的项数
	static int num;

	// 默认构造函数
	ARPTableItem() {
	}

	// 带参数的构造函数，用于初始化ARP表项的IP地址和MAC地址
	ARPTableItem(DWORD IP, BYTE MAC[6]) {
		this->IP = IP;
		for (int i = 0; i < 6; i++) {
			this->MAC[i] = MAC[i];
		}
		num = 0;
	}

	// 打印ARP表项的信息
	void print() {
		char* str = (char*)malloc(sizeof(char) * 16);
		iptostr(IP, str); // 将IP地址转换为字符串格式
		printf("IP: %s", str); // 打印IP地址
			printf("MAC: %02x-%02x-%02x-%02x-%02x-%02x", MAC[0], MAC[1], MAC[2],
				MAC[3], MAC[4], MAC[5]); // 打印MAC地址
	}

	// 插入函数，用于向ARP表中添加新的项
	static void insert(DWORD IP, BYTE MAC[6]) {
		arptable[num] = ARPTableItem(IP, MAC);
		num++;
	}

	// 查询函数，用于根据IP地址查找对应的MAC地址
	static bool lookup(DWORD ip, BYTE mac[6]) {
		memset(mac, 0, sizeof(mac)); // 清空mac数组
		int i = 0;
		for (i; i < num; i++) { // 遍历ARP表，查找匹配的项
			if (arptable[i].IP == ip) {
				for (int j = 0; j < 6; j++) {
					mac[j] = arptable[i].MAC[j]; // 将匹配项的MAC地址复制到mac数组中
				}
				return true; // 找到匹配项，返回true
			}
		}
		if (i == num) { // 遍历完ARP表仍未找到匹配项，打印错误信息并返回false
			printf("Error: no match ARP item!");
		}
		return false;
	}

}arptable[100]; // 定义一个静态数组arptable，用于存储ARP表项
int ARPTableItem::num = 0;

//初始化
void get_device() {
	char errbuf[PCAP_ERRBUF_SIZE]; // 错误信息缓存区

	// 获取网卡列表
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, // 获取本机的接口设备
		NULL, // 无需认证
		&alldevs, // 指向设备列表首部
		errbuf // 出错信息保存缓存区
	) == -1) {
		// 错误处理
		printf("Error: find devices failed! %s", errbuf);
			pcap_freealldevs(alldevs);
	}
	else {
		pcap_if_t* cur = alldevs;
		// 打印信息
		printf("All devices:");
			for (int i = 1; cur != NULL; i++) {
				printf("No.%d: %s", i, cur->description);
					cur = cur->next;
			}
		// 选择网口号
		printf("Choose an adapter: ");
			int num = 0;
		scanf("%d", &num);
		for (int i = 0; i < num - 1; i++) {
			alldevs = alldevs->next;
		}
		if (alldevs == NULL) {
			printf("Error: cannot find the adapter!");
				pcap_freealldevs(alldevs);
			return;
		}
		// 打开网口
		if ((adhandle = pcap_open(alldevs->name, // 设备名
			65536, // 要捕捉的数据包的部分
			// 65535保证能捕获到不同数据链路层上的每个数据包的全部内容
			PCAP_OPENFLAG_PROMISCUOUS, // 混杂模式
			1000, // 读取超时时间
			NULL, // 远程机器验证
			errbuf // 错误缓冲池
		)) == NULL) {
			printf("Error: adapter %s cannot be accessed!", alldevs->name);
				pcap_freealldevs(alldevs);
			return;
		}
		else {
			printf("Successfully open!");
				printf("Listening on %s...", alldevs->description);
		}
	}
}


//获取ip地址
void get_ip_netmask() {
	int i = 0; // 初始化计数器
	pcap_addr_t* addr = alldevs->addresses; // 获取设备的所有地址
	for (addr; addr != NULL; addr = addr->next) { // 遍历所有地址
		switch (addr->addr->sa_family) // 根据地址类型进行处理
		{
		case AF_INET: // IPv4地址
			myaddr[i] = *addr; // 将当前地址复制到myaddr数组中
			if (addr->addr) { // 如果当前地址有具体的IP地址
				char* ip_str = (char*)malloc(sizeof(char) * 16); // 分配内存存储IP地址字符串
				iptostr(((struct sockaddr_in*)addr->addr)->sin_addr.s_addr, ip_str); // 将IP地址转换为字符串格式
				printf("我的IP地址： %s\n", ip_str); // 打印IP地址
					myip[i] = (char*)malloc(sizeof(char) * 16); // 分配内存存储转换后的IP地址字符串
				memcpy(myip[i], ip_str, 16); // 将转换后的IP地址字符串复制到myip数组中
			}
			if (addr->netmask) { // 如果当前地址有子网掩码
				char* netmask_str = (char*)malloc(sizeof(char) * 16); // 分配内存存储子网掩码字符串
				iptostr(((struct sockaddr_in*)addr->netmask)->sin_addr.s_addr, netmask_str); // 将子网掩码转换为字符串格式
				printf("我的子网掩码： %s\n", netmask_str); // 打印子网掩码
					mynetmask[i] = (char*)malloc(sizeof(char) * 16); // 分配内存存储转换后的子网掩码字符串
				memcpy(mynetmask[i], netmask_str, 16); // 将转换后的子网掩码字符串复制到mynetmask数组中
			}
			i++; // 计数器加1
			break;
		case AF_INET6: // IPv6地址
			break;
		}
	}
}


//arp请求
void ARP_request(DWORD sendip, DWORD recvip, BYTE sendmac[6]) {
	ARPFrame_t packet; // 定义一个ARP帧结构体变量
	memset(packet.FrameHeader.DesMAC, 0xff, 6); // 将目的MAC地址设置为广播地址
	memcpy(packet.FrameHeader.SrcMAC, sendmac, 6); // 将源MAC地址复制到ARP帧中
	memcpy(packet.SendHa, sendmac, 6); // 将源硬件地址复制到ARP帧中
	memset(packet.RecvHa, 0x00, 6); // 将接收硬件地址设置为0
	packet.FrameHeader.FrameType = htons(ETH_ARP); // 设置帧类型为ARP
	packet.HardwareType = htons(ARP_HARDWARE); // 设置硬件类型为以太网
	packet.ProtocolType = htons(ETH_IP); // 设置协议类型为IPv4
	packet.HLen = 6; // 设置源硬件地址长度为6字节
	packet.PLen = 4; // 设置协议地址长度为4字节
	packet.Operation = htons(ARP_REQUEST); // 设置操作类型为ARP请求
	packet.SendIP = sendip; // 设置发送方IP地址
	packet.RecvIP = recvip; // 设置接收方IP地址
	if (pcap_sendpacket(adhandle, (u_char*)&packet, sizeof(packet)) == -1) // 发送ARP数据包
	{
		printf("发送ARP数据包失败！ 错误： %d\n", GetLastError()); // 输出错误信息
			return;
	}
	printf("发送ARP数据包成功！\n"); // 输出成功信息
		return;
}

void ARP_reply(DWORD recvip, BYTE mac[6]) {
	struct pcap_pkthdr* pkt_header; // 定义一个pcap包头结构体变量
	const u_char* pkt_data; // 定义一个指向数据包的指针变量
	memset(mac, 0, sizeof(mac)); // 将MAC地址数组清零
	int i = 0; // 初始化计数器
	while ((pcap_next_ex(adhandle, &pkt_header, &pkt_data)) >= 0) // 循环获取数据包
	{
		//find mac
		ARPFrame_t* tmp = (ARPFrame_t*)pkt_data; // 将数据包转换为ARP帧结构体指针
		if (tmp->Operation == htons(ARP_REPLY) // 如果操作类型为ARP回复且接收方IP地址匹配
			&& tmp->SendIP == recvip)
		{
			for (i = 0; i < 6; i++) { // 遍历源硬件地址数组
				mac[i] = tmp->SendHa[i]; // 将源硬件地址复制到目标MAC地址数组中
			}
			printf("Successfully get MAC!\n"); // 输出成功信息
				printf("MAC: %02x-%02x-%02x-%02x-%02x-%02x\n", mac[0], mac[1], mac[2],
					mac[3], mac[4], mac[5]); // 输出MAC地址
			char* ipstr = (char*)malloc(sizeof(char) * 16); // 分配内存空间用于存储IP地址字符串
			iptostr(recvip, ipstr); // 将IP地址转换为字符串格式
			printf("IP: %s\n", ipstr); // 输出IP地址
				break; // 跳出循环
		}
	}
	if (i != 6) // 如果计数器不等于6，表示未找到匹配的MAC地址
	{
		printf("Failed to get MAC!\n"); // 输出失败信息
	}
}

void get_other_mac(int index, char* ip, BYTE mac[6]) {
	// 发送ARP请求，获取指定IP地址的MAC地址
	ARP_request(inet_addr(myip[index]), inet_addr(ip), mymac[index]);
	// 接收ARP回复，将回复中的MAC地址存储到目标数组中
	ARP_reply(inet_addr(ip), mac);
}

//获取自身mac地址
void get_my_mac(int index) {
	// 定义发送的MAC地址和IP地址
	BYTE sendmac[6] = { 1,1,1,1,1,1 };
	DWORD sendip = inet_addr("100.100.100.100");

	// 获取目标IP地址对应的网络地址
	DWORD recvip = ((struct sockaddr_in*)myaddr[index].addr)->sin_addr.s_addr;
	// 发送ARP请求，获取本机IP地址对应的MAC地址
	ARP_request(sendip, recvip, sendmac);
	struct pcap_pkthdr* pkt_header;
	const u_char* pkt_data;
	int i = 0;
	// 循环接收数据包，查找本机的MAC地址
	while ((pcap_next_ex(adhandle, &pkt_header, &pkt_data)) >= 0)
	{
		//find my own mac
		ARPFrame_t* tmp = (ARPFrame_t*)pkt_data;
		// 如果收到的数据包是ARP回复，并且源IP地址和目标IP地址与发送的一致
		if (tmp->Operation == htons(ARP_REPLY)
			&& tmp->RecvIP == sendip
			&& tmp->SendIP == recvip)
		{
			// 将找到的MAC地址存储到目标数组中
			for (i = 0; i < 6; i++) {
				mymac[index][i] = tmp->SendHa[i];
			}
			//printf("Successfully get my MAC!\n");
			printf("我的MAC地址： %02x-%02x-%02x-%02x-%02x-%02x\n\n", mymac[index][0], mymac[index][1], mymac[index][2],
				mymac[index][3], mymac[index][4], mymac[index][5]);
			break;
		}
	}
	if (i != 6)
	{
		printf("无法获取我的MAC地址！\n");
	}
}


bool checkchecksum(Data_t* data) {
	unsigned int sum = 0; // 初始化校验和为0
	WORD* word = (WORD*)&data->IPHeader; // 将数据包的IP头部地址转换为WORD指针
	// 计算校验和
	for (int i = 0; i < sizeof(IPHeader_t) / 2; i++) { // 遍历IP头部的所有字节
		sum += word[i]; // 累加每个字节的值到校验和中
		while (sum >= 0x10000) { // 如果校验和大于等于65536，进行溢出处理
			int tmp = sum >> 16; // 将高16位的值赋给临时变量tmp
			sum -= 0x10000; // 减去高16位的值
			sum += tmp; // 加上低16位的值
		}
	}
	// 如果校验和等于65535，则返回true，否则返回false并打印错误信息
	if (sum == 65535) {
		return true;
	}
	printf("错误的校验和！");
		return false;
}

//填充校验和
void setchecksum(Data_t* data) {
	data->IPHeader.Checksum = 0; // 将数据包的校验和字段设置为0
	unsigned int sum = 0; // 初始化校验和为0
	WORD* word = (WORD*)&data->IPHeader; // 将数据包的IP头部地址转换为WORD指针
	// 计算校验和
	for (int i = 0; i < sizeof(IPHeader_t) / 2; i++) { // 遍历IP头部的所有字节
		sum += word[i]; // 累加每个字节的值到校验和中
		while (sum >= 0x10000) { // 如果校验和大于等于65536，进行溢出处理
			int tmp = sum >> 16; // 将高16位的值赋给临时变量tmp
			sum -= 0x10000; // 减去高16位的值
			sum += tmp; // 加上低16位的值
		}
	}
	// 将计算出的校验和取反后赋值给数据包的校验和字段
	data->IPHeader.Checksum = ~sum;
}


// 修改MAC地址并发送数据包
void sendpacket(ICMP_t data, BYTE dstmac[6]) {
	Data_t* tmp = (Data_t*)&data; // 将传入的数据结构指针转换为Data_t类型指针
	memcpy(tmp->FrameHeader.SrcMAC, tmp->FrameHeader.DesMAC, 6); // 将源MAC地址复制到目的MAC地址
	memcpy(tmp->FrameHeader.DesMAC, dstmac, 6); // 将目的MAC地址替换为传入的dstmac
	tmp->IPHeader.TTL--; // TTL减1
	if (tmp->IPHeader.TTL < 0) { // 如果TTL小于0，打印错误信息并返回
		printf("TTL invalid!\n");
		return;
	}
	setchecksum(tmp); // 设置校验和
	if (pcap_sendpacket(adhandle, (const u_char*)tmp, 74) == 0) { // 发送数据包
		printf("转发一个IP消息：\n");
		printf("源MAC: %02x-%02x-%02x-%02x-%02x-%02x\n",
			tmp->FrameHeader.SrcMAC[0], tmp->FrameHeader.SrcMAC[1],
			tmp->FrameHeader.SrcMAC[2], tmp->FrameHeader.SrcMAC[3],
			tmp->FrameHeader.SrcMAC[4], tmp->FrameHeader.SrcMAC[5]);
		printf("目的MAC: %02x-%02x-%02x-%02x-%02x-%02x\n",
			tmp->FrameHeader.DesMAC[0], tmp->FrameHeader.DesMAC[1],
			tmp->FrameHeader.DesMAC[2], tmp->FrameHeader.DesMAC[3],
			tmp->FrameHeader.DesMAC[4], tmp->FrameHeader.DesMAC[5]);
		char* src = (char*)malloc(sizeof(char) * 16); // 分配内存存储源IP地址
		char* dst = (char*)malloc(sizeof(char) * 16); // 分配内存存储目的IP地址
		iptostr(tmp->IPHeader.SrcIP, src); // 将源IP地址转换为字符串
		iptostr(tmp->IPHeader.DstIP, dst); // 将目的IP地址转换为字符串
		printf("源IP: %s\n", src); // 打印源IP地址
		printf("目的IP: %s\n", dst); // 打印目的IP地址
		printf("TTL: %d\n\n", tmp->IPHeader.TTL); // 打印TTL值
	}
}

// 比较两个MAC地址是否相同
bool MACcmp(BYTE MAC1[], BYTE MAC2[]) {
	for (int i = 0; i < 6; i++) { // 遍历每个字节
		if (MAC1[i] != MAC2[i]) { // 如果发现不同的字节，返回false
			return false;
		}
	}
	return true; // 如果所有字节都相同，返回true
}

void work(RouteTable* routetable) {
	memset(broadcastmac, 0xff, 6); // 将广播MAC地址设置为全1
	clock_t start, end; // 定义开始和结束时间变量
	start = clock(); // 记录开始时间
	while (true) {
		end = clock(); // 记录结束时间
		printf("time=%f", (double)(end - start) / CLK_TCK); // 输出运行时间
			if ((double)(end - start) / CLK_TCK > MAX_WORK_TIME) { // 如果运行时间超过最大工作时间
				printf("Timed out!"); // 输出超时信息
					break; // 跳出循环
			}
		pcap_pkthdr* pkt_header; // 定义数据包头指针
		const u_char* pkt_data; // 定义数据包内容指针
		// 捕获数据包
		while (true) { // 无限循环，直到满足某个条件才跳出循环
			if (pcap_next_ex(adhandle, &pkt_header, &pkt_data) > 0) { // 调用pcap库函数，获取下一个数据包
				// 获取一个数据包！
				FrameHeader_t* tmp = (FrameHeader_t*)pkt_data; // 将数据包的数据部分转换为FrameHeader_t结构体指针
				if (MACcmp(tmp->DesMAC, mymac[0]) && (ntohs(tmp->FrameType) == ETH_IP)) { // 判断数据包的目的MAC地址是否与mymac[0]相同，以及帧类型是否为以太网IP帧
					break; // 如果满足条件，跳出循环
				}
				continue; // 如果不满足条件，继续下一次循环
			}
		}

		FrameHeader_t* frame_header = (FrameHeader_t*)pkt_data;

		if (MACcmp(frame_header->DesMAC, mymac[0])) {
			if (ntohs(frame_header->FrameType) == ETH_IP) {
				Data_t* data = (Data_t*)pkt_data;
				printf("\nRecieve an IP message:\n");
				printf("Src MAC: %02x-%02x-%02x-%02x-%02x-%02x\n",
					data->FrameHeader.SrcMAC[0], data->FrameHeader.SrcMAC[1],
					data->FrameHeader.SrcMAC[2], data->FrameHeader.SrcMAC[3],
					data->FrameHeader.SrcMAC[4], data->FrameHeader.SrcMAC[5]);
				printf("Des MAC: %02x-%02x-%02x-%02x-%02x-%02x\n",
					data->FrameHeader.DesMAC[0], data->FrameHeader.DesMAC[1],
					data->FrameHeader.DesMAC[2], data->FrameHeader.DesMAC[3],
					data->FrameHeader.DesMAC[4], data->FrameHeader.DesMAC[5]);
				char* src = (char*)malloc(sizeof(char) * 16);
				char* dst = (char*)malloc(sizeof(char) * 16);
				iptostr(data->IPHeader.SrcIP, src);
				iptostr(data->IPHeader.DstIP, dst);
				printf("Src IP: %s\n", src);
				printf("Des IP: %s\n", dst);
				printf("TTL: %d\n\n", data->IPHeader.TTL);


				DWORD dstip = data->IPHeader.DstIP;
				DWORD midip = routetable->lookup(dstip); //查找路由表中是否有对应表项
				if (midip == -1) { //如果没有则直接丢弃或直接递交至上层
					continue; //do nothing
				}

				if (checkchecksum(data)) { //如果校验和不正确，则直接丢弃不进行处理
					if (data->IPHeader.DstIP != inet_addr(myip[0])
						&& data->IPHeader.DstIP != inet_addr(myip[1])) {
						//不是广播消息
						int res1 = MACcmp(data->FrameHeader.DesMAC, broadcastmac);
						int res2 = MACcmp(data->FrameHeader.SrcMAC, broadcastmac);
						if (!res1 && !res2) {
							//ICMP报文包含IP数据包报头和其它内容
							ICMP_t* icmp_ptr = (ICMP_t*)pkt_data;
							ICMP_t icmp = *icmp_ptr;
							BYTE* mac = (BYTE*)malloc(sizeof(BYTE) * 6);
							if (midip == 0) { //直接投递，查找目的IP的MAc
								//find arp
								if (ARPTableItem::lookup(dstip, mac) == 0) {
									printf("Cannot find matched ARP!\n");
									char* dst = (char*)malloc(sizeof(char) * 16);
									iptostr(dstip, dst);
									get_other_mac(0, dst, mac);
									ARPTableItem::insert(dstip, mac);
								}
								printf("\nnexthop: %s\n", dst);
								sendpacket(icmp, mac);
							}
							else if (midip != -1) { //非直接投递，查找下一条IP的MAC
								//find arp for midip								
								if (ARPTableItem::lookup(midip, mac) == 0) {
									printf("Cannot find matched ARP!\n");
									char* dst = (char*)malloc(sizeof(char) * 16);
									iptostr(midip, dst);
									//printf("999 %s\n", dst);
									get_other_mac(0, dst, mac);
									ARPTableItem::insert(midip, mac);
								}
								printf("\nnexthop: %s\n", dst);
								sendpacket(icmp, mac);
							}
						}
					}
				}
				else {
					printf("Error: wrong checksum!\n");
				}
			}
		}
	}
}


void endwork() {
	pcap_freealldevs(alldevs);
}

int main() {
	get_device();  // 获取网络设备信息
	get_ip_netmask();  // 获取本机 IP 和子网掩码信息
	RouteTable* routetable = new RouteTable();  // 创建路由表对象
	get_my_mac(0);  // 获取本机 MAC 地址

	routetable->print();  // 打印当前路由表信息

	printf("添加路由表项：\n");
	printf("Dst net: ");
	char dstnet[1024] = { 0 };
	scanf("%s", dstnet);
	printf("\nNetmask: ");
	char netmask[1024] = { 0 };
	scanf("%s", netmask);
	printf("\nNext Hop: ");
	char nexthop[1024] = { 0 };
	scanf("%s", nexthop);

	// 创建新的路由表项
	RouteTableItem* newitem = new RouteTableItem();
	newitem->dstnet = inet_addr(dstnet);
	newitem->netmask = inet_addr(netmask);
	newitem->nextip = inet_addr(nexthop);
	newitem->type = 1;
	routetable->add(newitem);  // 添加新的路由表项
	printf("成功添加路由表项!\n");

	int d = 0;
	while (true) {
		printf("是否删除路由表项：");
		scanf("%d", &d);
		if (d != 0) {
			routetable->remove(d - 1);  // 删除指定索引的路由表项
			routetable->print();
		}
		else {
			break;
		}
	}

	ARPTableItem::insert(inet_addr(myip[0]), mymac[0]);  // 向 ARP 表中插入条目
	ARPTableItem::insert(inet_addr(myip[1]), mymac[1]);

	routetable->print();  // 打印最终路由表信息
	for (int i = 0; i < ARPTableItem::num; i++) {
		arptable[i].print();  // 打印 ARP 表中的条目信息
	}
	work(routetable);  // 执行工作函数

	endwork();  // 结束工作，释放资源
	return 0;
}