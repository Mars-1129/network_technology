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

//·�ɱ���
class RouteTableItem {
public:
	DWORD netmask; //��������
	DWORD dstnet; //Ŀ�������ַ
	DWORD nextip; //��һ��IP��ַ
	int type; //���ͣ�0Ϊֱ�����ӣ�1Ϊ�û����
	RouteTableItem* nextitem; //ָ����һ��·�ɱ����ָ�룬����������ʽ�洢
	RouteTableItem() {
		memset(this, 0, sizeof(*this)); //��ʼ��·�ɱ���ĳ�Ա����Ϊ0
	}
	RouteTableItem(DWORD netmask, DWORD dstnet, int type, DWORD nextip = 0) {
		this->netmask = netmask; //������������
		this->dstnet = dstnet; //����Ŀ�������ַ
		this->nextip = nextip; //������һ��IP��ַ��Ĭ��Ϊ0
		this->type = type; //�������ͣ�Ĭ��Ϊ0
	}
	void print() {
		char* str = (char*)malloc(sizeof(char) * 16); //�����ڴ�ռ����ڴ洢IP��ַ�ַ���
		iptostr(netmask, str); //����������ת��Ϊ�ַ���
		printf("Netmask: %s\n", str); //�����������
		iptostr(dstnet, str); //��Ŀ�������ַת��Ϊ�ַ���
		printf("Destination: %s\n", str); //���Ŀ�������ַ
		iptostr(nextip, str); //����һ��IP��ַת��Ϊ�ַ���
		printf("Next ip: %s\n", str); //�����һ��IP��ַ
		printf("Type: %d\n", type); //�������
	}
};

//·�ɱ�
class RouteTable {
public:
	RouteTableItem* head; // ͷָ��
	RouteTableItem* tail; // βָ��
	int num; // ·�ɱ��е�����

	RouteTable() {
		DWORD netmask = inet_addr(mynetmask[0]); // ����������ת��Ϊ32λ����
		DWORD dstnet = (inet_addr(myip[0])) & (inet_addr(mynetmask[0])); // ����Ŀ�������ַ
		int type = 0; // ����Ϊ0��ʾֱ�ӷ���
		head = new RouteTableItem(netmask, dstnet, type); // ����ͷ�ڵ�
		tail = new RouteTableItem; // ������β�ڵ�
		head->nextitem = tail; // ͷ�ڵ�ָ��β�ڵ�

		RouteTableItem* tmp = new RouteTableItem; // ������ʱ�ڵ���������µ�·�ɱ���
		tmp->dstnet = (inet_addr(myip[1])) & (inet_addr(mynetmask[1])); // ����ڶ���Ŀ�������ַ
		tmp->netmask = inet_addr(mynetmask[1]); // ������������
		tmp->type = 0; // ����Ϊ0��ʾֱ�ӷ���
		//tmp->nextip = (inet_addr(myip[1])); // ��ʱ��������һ��IP��ַ
		add(tmp); // ����µ�·�ɱ���
		num = 2; // ·�ɱ�����2��IP��ַ
	}

	// ��ӱ��ֱ��Ͷ������ǰ��ǰ׺������ǰ�棩
	void add(RouteTableItem* newitem) {
		num++; // ����·�ɱ��е�����
		// ������������Ϊ0����ֱ����ӵ�ͷ�ڵ�֮��
		if (newitem->type == 0) {
			newitem->nextitem = head->nextitem;
			head->nextitem = newitem;
			return;
		}
		// �����������Ͳ�Ϊ0���������������ĳ��Ƚ�������
		RouteTableItem* cur = head;
		while (cur->nextitem != tail) {
			if (cur->nextitem->type != 0 && cur->nextitem->netmask < newitem->netmask) {
				break;
			}
			cur = cur->nextitem;
		}
		// ��������뵽��ǰ�ڵ����һ���ڵ�֮��
		newitem->nextitem = cur->nextitem;
		cur->nextitem = newitem;
	}

	// ɾ������
	void remove(int index) {
		if (index >= num) { // �������������Χ�����ӡ������Ϣ������
			printf("·�ɱ���%d������Χ��\n", index);
			return;
		}
		if (index == 0) { // �������Ϊ0����ɾ��ͷ�ڵ�
			if (head->type == 0) {
				printf("��·�ɱ����ɾ����\n");
			}
			else {
				head = head->nextitem;
			}
			return;
		}
		RouteTableItem* cur = head;
		int i = 0;
		while (i < index - 1 && cur->nextitem != tail) { // �ҵ�Ҫɾ���Ľڵ��ǰһ���ڵ�
			i++;
			cur = cur->nextitem;
		}
		if (cur->nextitem->type == 0) { // ���Ҫɾ���Ľڵ�����Ϊ0�����ӡ������Ϣ������
			printf("��·�ɱ����ɾ����\n");
		}
		else {
			cur->nextitem = cur->nextitem->nextitem; // ���򣬽�Ҫɾ���Ľڵ���������Ƴ�
		}
	}

	// ��ӡ·�ɱ�
	void print() {
		printf("Route Table:\n");
		RouteTableItem* cur = head;
		int i = 1;
		while (cur != tail) {
			printf("No.%d:\n", i);
			cur->print(); // ����ÿ���ڵ��print�������д�ӡ
			cur = cur->nextitem;
			i++;
		}
	}

	// ���ң��ǰ׺��������һ����ip
	DWORD lookup(DWORD dstip) {
		DWORD res;
		RouteTableItem* cur = head;
		while (cur != tail) {
			res = dstip & cur->netmask; // ����Ŀ��IP��ַ�뵱ǰ�ڵ����������İ�λ����
			if (res == cur->dstnet) { // ���������ڵ�ǰ�ڵ��Ŀ�������ַ�����ʾ�ҵ����ǰ׺
				if (cur->type != 0) { // �����ǰ�ڵ�����Ͳ�Ϊ0�����ʾ��Ҫת����������һ��IP��ַ
					return cur->nextip;
				}
				else { // �����ǰ�ڵ������Ϊ0�����ʾ����ֱ�ӷ��ͣ�����0
					return 0;
				}
			}
			cur = cur->nextitem; // ����������һ���ڵ�
		}
		printf("û���ҵ���Ӧ��·�ɱ��\n"); // ������������нڵ㶼û���ҵ�ƥ�������ӡ������Ϣ������-1
		return -1;
	}
};

class ARPTableItem {
public:
	// IP��ַ��ʹ��DWORD���ͱ�ʾ
	DWORD IP;
	// MAC��ַ��ʹ��BYTE�����ʾ������Ϊ6
	BYTE MAC[6];
	// ��̬���������ڼ�¼ARP���е�����
	static int num;

	// Ĭ�Ϲ��캯��
	ARPTableItem() {
	}

	// �������Ĺ��캯�������ڳ�ʼ��ARP�����IP��ַ��MAC��ַ
	ARPTableItem(DWORD IP, BYTE MAC[6]) {
		this->IP = IP;
		for (int i = 0; i < 6; i++) {
			this->MAC[i] = MAC[i];
		}
		num = 0;
	}

	// ��ӡARP�������Ϣ
	void print() {
		char* str = (char*)malloc(sizeof(char) * 16);
		iptostr(IP, str); // ��IP��ַת��Ϊ�ַ�����ʽ
		printf("IP: %s", str); // ��ӡIP��ַ
			printf("MAC: %02x-%02x-%02x-%02x-%02x-%02x", MAC[0], MAC[1], MAC[2],
				MAC[3], MAC[4], MAC[5]); // ��ӡMAC��ַ
	}

	// ���뺯����������ARP��������µ���
	static void insert(DWORD IP, BYTE MAC[6]) {
		arptable[num] = ARPTableItem(IP, MAC);
		num++;
	}

	// ��ѯ���������ڸ���IP��ַ���Ҷ�Ӧ��MAC��ַ
	static bool lookup(DWORD ip, BYTE mac[6]) {
		memset(mac, 0, sizeof(mac)); // ���mac����
		int i = 0;
		for (i; i < num; i++) { // ����ARP������ƥ�����
			if (arptable[i].IP == ip) {
				for (int j = 0; j < 6; j++) {
					mac[j] = arptable[i].MAC[j]; // ��ƥ�����MAC��ַ���Ƶ�mac������
				}
				return true; // �ҵ�ƥ�������true
			}
		}
		if (i == num) { // ������ARP����δ�ҵ�ƥ�����ӡ������Ϣ������false
			printf("Error: no match ARP item!");
		}
		return false;
	}

}arptable[100]; // ����һ����̬����arptable�����ڴ洢ARP����
int ARPTableItem::num = 0;

//��ʼ��
void get_device() {
	char errbuf[PCAP_ERRBUF_SIZE]; // ������Ϣ������

	// ��ȡ�����б�
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, // ��ȡ�����Ľӿ��豸
		NULL, // ������֤
		&alldevs, // ָ���豸�б��ײ�
		errbuf // ������Ϣ���滺����
	) == -1) {
		// ������
		printf("Error: find devices failed! %s", errbuf);
			pcap_freealldevs(alldevs);
	}
	else {
		pcap_if_t* cur = alldevs;
		// ��ӡ��Ϣ
		printf("All devices:");
			for (int i = 1; cur != NULL; i++) {
				printf("No.%d: %s", i, cur->description);
					cur = cur->next;
			}
		// ѡ�����ں�
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
		// ������
		if ((adhandle = pcap_open(alldevs->name, // �豸��
			65536, // Ҫ��׽�����ݰ��Ĳ���
			// 65535��֤�ܲ��񵽲�ͬ������·���ϵ�ÿ�����ݰ���ȫ������
			PCAP_OPENFLAG_PROMISCUOUS, // ����ģʽ
			1000, // ��ȡ��ʱʱ��
			NULL, // Զ�̻�����֤
			errbuf // ���󻺳��
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


//��ȡip��ַ
void get_ip_netmask() {
	int i = 0; // ��ʼ��������
	pcap_addr_t* addr = alldevs->addresses; // ��ȡ�豸�����е�ַ
	for (addr; addr != NULL; addr = addr->next) { // �������е�ַ
		switch (addr->addr->sa_family) // ���ݵ�ַ���ͽ��д���
		{
		case AF_INET: // IPv4��ַ
			myaddr[i] = *addr; // ����ǰ��ַ���Ƶ�myaddr������
			if (addr->addr) { // �����ǰ��ַ�о����IP��ַ
				char* ip_str = (char*)malloc(sizeof(char) * 16); // �����ڴ�洢IP��ַ�ַ���
				iptostr(((struct sockaddr_in*)addr->addr)->sin_addr.s_addr, ip_str); // ��IP��ַת��Ϊ�ַ�����ʽ
				printf("�ҵ�IP��ַ�� %s\n", ip_str); // ��ӡIP��ַ
					myip[i] = (char*)malloc(sizeof(char) * 16); // �����ڴ�洢ת�����IP��ַ�ַ���
				memcpy(myip[i], ip_str, 16); // ��ת�����IP��ַ�ַ������Ƶ�myip������
			}
			if (addr->netmask) { // �����ǰ��ַ����������
				char* netmask_str = (char*)malloc(sizeof(char) * 16); // �����ڴ�洢���������ַ���
				iptostr(((struct sockaddr_in*)addr->netmask)->sin_addr.s_addr, netmask_str); // ����������ת��Ϊ�ַ�����ʽ
				printf("�ҵ��������룺 %s\n", netmask_str); // ��ӡ��������
					mynetmask[i] = (char*)malloc(sizeof(char) * 16); // �����ڴ�洢ת��������������ַ���
				memcpy(mynetmask[i], netmask_str, 16); // ��ת��������������ַ������Ƶ�mynetmask������
			}
			i++; // ��������1
			break;
		case AF_INET6: // IPv6��ַ
			break;
		}
	}
}


//arp����
void ARP_request(DWORD sendip, DWORD recvip, BYTE sendmac[6]) {
	ARPFrame_t packet; // ����һ��ARP֡�ṹ�����
	memset(packet.FrameHeader.DesMAC, 0xff, 6); // ��Ŀ��MAC��ַ����Ϊ�㲥��ַ
	memcpy(packet.FrameHeader.SrcMAC, sendmac, 6); // ��ԴMAC��ַ���Ƶ�ARP֡��
	memcpy(packet.SendHa, sendmac, 6); // ��ԴӲ����ַ���Ƶ�ARP֡��
	memset(packet.RecvHa, 0x00, 6); // ������Ӳ����ַ����Ϊ0
	packet.FrameHeader.FrameType = htons(ETH_ARP); // ����֡����ΪARP
	packet.HardwareType = htons(ARP_HARDWARE); // ����Ӳ������Ϊ��̫��
	packet.ProtocolType = htons(ETH_IP); // ����Э������ΪIPv4
	packet.HLen = 6; // ����ԴӲ����ַ����Ϊ6�ֽ�
	packet.PLen = 4; // ����Э���ַ����Ϊ4�ֽ�
	packet.Operation = htons(ARP_REQUEST); // ���ò�������ΪARP����
	packet.SendIP = sendip; // ���÷��ͷ�IP��ַ
	packet.RecvIP = recvip; // ���ý��շ�IP��ַ
	if (pcap_sendpacket(adhandle, (u_char*)&packet, sizeof(packet)) == -1) // ����ARP���ݰ�
	{
		printf("����ARP���ݰ�ʧ�ܣ� ���� %d\n", GetLastError()); // ���������Ϣ
			return;
	}
	printf("����ARP���ݰ��ɹ���\n"); // ����ɹ���Ϣ
		return;
}

void ARP_reply(DWORD recvip, BYTE mac[6]) {
	struct pcap_pkthdr* pkt_header; // ����һ��pcap��ͷ�ṹ�����
	const u_char* pkt_data; // ����һ��ָ�����ݰ���ָ�����
	memset(mac, 0, sizeof(mac)); // ��MAC��ַ��������
	int i = 0; // ��ʼ��������
	while ((pcap_next_ex(adhandle, &pkt_header, &pkt_data)) >= 0) // ѭ����ȡ���ݰ�
	{
		//find mac
		ARPFrame_t* tmp = (ARPFrame_t*)pkt_data; // �����ݰ�ת��ΪARP֡�ṹ��ָ��
		if (tmp->Operation == htons(ARP_REPLY) // �����������ΪARP�ظ��ҽ��շ�IP��ַƥ��
			&& tmp->SendIP == recvip)
		{
			for (i = 0; i < 6; i++) { // ����ԴӲ����ַ����
				mac[i] = tmp->SendHa[i]; // ��ԴӲ����ַ���Ƶ�Ŀ��MAC��ַ������
			}
			printf("Successfully get MAC!\n"); // ����ɹ���Ϣ
				printf("MAC: %02x-%02x-%02x-%02x-%02x-%02x\n", mac[0], mac[1], mac[2],
					mac[3], mac[4], mac[5]); // ���MAC��ַ
			char* ipstr = (char*)malloc(sizeof(char) * 16); // �����ڴ�ռ����ڴ洢IP��ַ�ַ���
			iptostr(recvip, ipstr); // ��IP��ַת��Ϊ�ַ�����ʽ
			printf("IP: %s\n", ipstr); // ���IP��ַ
				break; // ����ѭ��
		}
	}
	if (i != 6) // ���������������6����ʾδ�ҵ�ƥ���MAC��ַ
	{
		printf("Failed to get MAC!\n"); // ���ʧ����Ϣ
	}
}

void get_other_mac(int index, char* ip, BYTE mac[6]) {
	// ����ARP���󣬻�ȡָ��IP��ַ��MAC��ַ
	ARP_request(inet_addr(myip[index]), inet_addr(ip), mymac[index]);
	// ����ARP�ظ������ظ��е�MAC��ַ�洢��Ŀ��������
	ARP_reply(inet_addr(ip), mac);
}

//��ȡ����mac��ַ
void get_my_mac(int index) {
	// ���巢�͵�MAC��ַ��IP��ַ
	BYTE sendmac[6] = { 1,1,1,1,1,1 };
	DWORD sendip = inet_addr("100.100.100.100");

	// ��ȡĿ��IP��ַ��Ӧ�������ַ
	DWORD recvip = ((struct sockaddr_in*)myaddr[index].addr)->sin_addr.s_addr;
	// ����ARP���󣬻�ȡ����IP��ַ��Ӧ��MAC��ַ
	ARP_request(sendip, recvip, sendmac);
	struct pcap_pkthdr* pkt_header;
	const u_char* pkt_data;
	int i = 0;
	// ѭ���������ݰ������ұ�����MAC��ַ
	while ((pcap_next_ex(adhandle, &pkt_header, &pkt_data)) >= 0)
	{
		//find my own mac
		ARPFrame_t* tmp = (ARPFrame_t*)pkt_data;
		// ����յ������ݰ���ARP�ظ�������ԴIP��ַ��Ŀ��IP��ַ�뷢�͵�һ��
		if (tmp->Operation == htons(ARP_REPLY)
			&& tmp->RecvIP == sendip
			&& tmp->SendIP == recvip)
		{
			// ���ҵ���MAC��ַ�洢��Ŀ��������
			for (i = 0; i < 6; i++) {
				mymac[index][i] = tmp->SendHa[i];
			}
			//printf("Successfully get my MAC!\n");
			printf("�ҵ�MAC��ַ�� %02x-%02x-%02x-%02x-%02x-%02x\n\n", mymac[index][0], mymac[index][1], mymac[index][2],
				mymac[index][3], mymac[index][4], mymac[index][5]);
			break;
		}
	}
	if (i != 6)
	{
		printf("�޷���ȡ�ҵ�MAC��ַ��\n");
	}
}


bool checkchecksum(Data_t* data) {
	unsigned int sum = 0; // ��ʼ��У���Ϊ0
	WORD* word = (WORD*)&data->IPHeader; // �����ݰ���IPͷ����ַת��ΪWORDָ��
	// ����У���
	for (int i = 0; i < sizeof(IPHeader_t) / 2; i++) { // ����IPͷ���������ֽ�
		sum += word[i]; // �ۼ�ÿ���ֽڵ�ֵ��У�����
		while (sum >= 0x10000) { // ���У��ʹ��ڵ���65536�������������
			int tmp = sum >> 16; // ����16λ��ֵ������ʱ����tmp
			sum -= 0x10000; // ��ȥ��16λ��ֵ
			sum += tmp; // ���ϵ�16λ��ֵ
		}
	}
	// ���У��͵���65535���򷵻�true�����򷵻�false����ӡ������Ϣ
	if (sum == 65535) {
		return true;
	}
	printf("�����У��ͣ�");
		return false;
}

//���У���
void setchecksum(Data_t* data) {
	data->IPHeader.Checksum = 0; // �����ݰ���У����ֶ�����Ϊ0
	unsigned int sum = 0; // ��ʼ��У���Ϊ0
	WORD* word = (WORD*)&data->IPHeader; // �����ݰ���IPͷ����ַת��ΪWORDָ��
	// ����У���
	for (int i = 0; i < sizeof(IPHeader_t) / 2; i++) { // ����IPͷ���������ֽ�
		sum += word[i]; // �ۼ�ÿ���ֽڵ�ֵ��У�����
		while (sum >= 0x10000) { // ���У��ʹ��ڵ���65536�������������
			int tmp = sum >> 16; // ����16λ��ֵ������ʱ����tmp
			sum -= 0x10000; // ��ȥ��16λ��ֵ
			sum += tmp; // ���ϵ�16λ��ֵ
		}
	}
	// ���������У���ȡ����ֵ�����ݰ���У����ֶ�
	data->IPHeader.Checksum = ~sum;
}


// �޸�MAC��ַ���������ݰ�
void sendpacket(ICMP_t data, BYTE dstmac[6]) {
	Data_t* tmp = (Data_t*)&data; // ����������ݽṹָ��ת��ΪData_t����ָ��
	memcpy(tmp->FrameHeader.SrcMAC, tmp->FrameHeader.DesMAC, 6); // ��ԴMAC��ַ���Ƶ�Ŀ��MAC��ַ
	memcpy(tmp->FrameHeader.DesMAC, dstmac, 6); // ��Ŀ��MAC��ַ�滻Ϊ�����dstmac
	tmp->IPHeader.TTL--; // TTL��1
	if (tmp->IPHeader.TTL < 0) { // ���TTLС��0����ӡ������Ϣ������
		printf("TTL invalid!\n");
		return;
	}
	setchecksum(tmp); // ����У���
	if (pcap_sendpacket(adhandle, (const u_char*)tmp, 74) == 0) { // �������ݰ�
		printf("ת��һ��IP��Ϣ��\n");
		printf("ԴMAC: %02x-%02x-%02x-%02x-%02x-%02x\n",
			tmp->FrameHeader.SrcMAC[0], tmp->FrameHeader.SrcMAC[1],
			tmp->FrameHeader.SrcMAC[2], tmp->FrameHeader.SrcMAC[3],
			tmp->FrameHeader.SrcMAC[4], tmp->FrameHeader.SrcMAC[5]);
		printf("Ŀ��MAC: %02x-%02x-%02x-%02x-%02x-%02x\n",
			tmp->FrameHeader.DesMAC[0], tmp->FrameHeader.DesMAC[1],
			tmp->FrameHeader.DesMAC[2], tmp->FrameHeader.DesMAC[3],
			tmp->FrameHeader.DesMAC[4], tmp->FrameHeader.DesMAC[5]);
		char* src = (char*)malloc(sizeof(char) * 16); // �����ڴ�洢ԴIP��ַ
		char* dst = (char*)malloc(sizeof(char) * 16); // �����ڴ�洢Ŀ��IP��ַ
		iptostr(tmp->IPHeader.SrcIP, src); // ��ԴIP��ַת��Ϊ�ַ���
		iptostr(tmp->IPHeader.DstIP, dst); // ��Ŀ��IP��ַת��Ϊ�ַ���
		printf("ԴIP: %s\n", src); // ��ӡԴIP��ַ
		printf("Ŀ��IP: %s\n", dst); // ��ӡĿ��IP��ַ
		printf("TTL: %d\n\n", tmp->IPHeader.TTL); // ��ӡTTLֵ
	}
}

// �Ƚ�����MAC��ַ�Ƿ���ͬ
bool MACcmp(BYTE MAC1[], BYTE MAC2[]) {
	for (int i = 0; i < 6; i++) { // ����ÿ���ֽ�
		if (MAC1[i] != MAC2[i]) { // ������ֲ�ͬ���ֽڣ�����false
			return false;
		}
	}
	return true; // ��������ֽڶ���ͬ������true
}

void work(RouteTable* routetable) {
	memset(broadcastmac, 0xff, 6); // ���㲥MAC��ַ����Ϊȫ1
	clock_t start, end; // ���忪ʼ�ͽ���ʱ�����
	start = clock(); // ��¼��ʼʱ��
	while (true) {
		end = clock(); // ��¼����ʱ��
		printf("time=%f", (double)(end - start) / CLK_TCK); // �������ʱ��
			if ((double)(end - start) / CLK_TCK > MAX_WORK_TIME) { // �������ʱ�䳬�������ʱ��
				printf("Timed out!"); // �����ʱ��Ϣ
					break; // ����ѭ��
			}
		pcap_pkthdr* pkt_header; // �������ݰ�ͷָ��
		const u_char* pkt_data; // �������ݰ�����ָ��
		// �������ݰ�
		while (true) { // ����ѭ����ֱ������ĳ������������ѭ��
			if (pcap_next_ex(adhandle, &pkt_header, &pkt_data) > 0) { // ����pcap�⺯������ȡ��һ�����ݰ�
				// ��ȡһ�����ݰ���
				FrameHeader_t* tmp = (FrameHeader_t*)pkt_data; // �����ݰ������ݲ���ת��ΪFrameHeader_t�ṹ��ָ��
				if (MACcmp(tmp->DesMAC, mymac[0]) && (ntohs(tmp->FrameType) == ETH_IP)) { // �ж����ݰ���Ŀ��MAC��ַ�Ƿ���mymac[0]��ͬ���Լ�֡�����Ƿ�Ϊ��̫��IP֡
					break; // �����������������ѭ��
				}
				continue; // ���������������������һ��ѭ��
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
				DWORD midip = routetable->lookup(dstip); //����·�ɱ����Ƿ��ж�Ӧ����
				if (midip == -1) { //���û����ֱ�Ӷ�����ֱ�ӵݽ����ϲ�
					continue; //do nothing
				}

				if (checkchecksum(data)) { //���У��Ͳ���ȷ����ֱ�Ӷ��������д���
					if (data->IPHeader.DstIP != inet_addr(myip[0])
						&& data->IPHeader.DstIP != inet_addr(myip[1])) {
						//���ǹ㲥��Ϣ
						int res1 = MACcmp(data->FrameHeader.DesMAC, broadcastmac);
						int res2 = MACcmp(data->FrameHeader.SrcMAC, broadcastmac);
						if (!res1 && !res2) {
							//ICMP���İ���IP���ݰ���ͷ����������
							ICMP_t* icmp_ptr = (ICMP_t*)pkt_data;
							ICMP_t icmp = *icmp_ptr;
							BYTE* mac = (BYTE*)malloc(sizeof(BYTE) * 6);
							if (midip == 0) { //ֱ��Ͷ�ݣ�����Ŀ��IP��MAc
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
							else if (midip != -1) { //��ֱ��Ͷ�ݣ�������һ��IP��MAC
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
	get_device();  // ��ȡ�����豸��Ϣ
	get_ip_netmask();  // ��ȡ���� IP ������������Ϣ
	RouteTable* routetable = new RouteTable();  // ����·�ɱ����
	get_my_mac(0);  // ��ȡ���� MAC ��ַ

	routetable->print();  // ��ӡ��ǰ·�ɱ���Ϣ

	printf("���·�ɱ��\n");
	printf("Dst net: ");
	char dstnet[1024] = { 0 };
	scanf("%s", dstnet);
	printf("\nNetmask: ");
	char netmask[1024] = { 0 };
	scanf("%s", netmask);
	printf("\nNext Hop: ");
	char nexthop[1024] = { 0 };
	scanf("%s", nexthop);

	// �����µ�·�ɱ���
	RouteTableItem* newitem = new RouteTableItem();
	newitem->dstnet = inet_addr(dstnet);
	newitem->netmask = inet_addr(netmask);
	newitem->nextip = inet_addr(nexthop);
	newitem->type = 1;
	routetable->add(newitem);  // ����µ�·�ɱ���
	printf("�ɹ����·�ɱ���!\n");

	int d = 0;
	while (true) {
		printf("�Ƿ�ɾ��·�ɱ��");
		scanf("%d", &d);
		if (d != 0) {
			routetable->remove(d - 1);  // ɾ��ָ��������·�ɱ���
			routetable->print();
		}
		else {
			break;
		}
	}

	ARPTableItem::insert(inet_addr(myip[0]), mymac[0]);  // �� ARP ���в�����Ŀ
	ARPTableItem::insert(inet_addr(myip[1]), mymac[1]);

	routetable->print();  // ��ӡ����·�ɱ���Ϣ
	for (int i = 0; i < ARPTableItem::num; i++) {
		arptable[i].print();  // ��ӡ ARP ���е���Ŀ��Ϣ
	}
	work(routetable);  // ִ�й�������

	endwork();  // �����������ͷ���Դ
	return 0;
}