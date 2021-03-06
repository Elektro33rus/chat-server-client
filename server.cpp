#include <iostream>
#include <winsock2.h>
#include <thread>
#include <vector>
#include <myhash>
#include <myhash2>
#include <ShellAPI.h>
#include <windows.h>
#include <cstdio>
#include <tlhelp32.h>

#pragma comment (lib, "Ws2_32.lib")

TCHAR *IP_ADDRESS;
TCHAR *DEFAULT_PORT;
#define DEFAULT_BUFLEN 512
int num_clients = 0;
const char OPTION_VALUE = 1;
const int MAX_CLIENTS = 10000;

struct client_type
{
	std::string nickname;
	std::string password;
	int id;
	SOCKET socket;
};


int process_client(client_type &new_client, std::vector<client_type> &client_array, std::thread &thread)
{
	SetConsoleCP(1251);
	SetConsoleOutputCP(1251);
	std::string msg = "";
	char tempmsg[DEFAULT_BUFLEN] = "";
	while (1)
	{
		srand(time(NULL));
		memset(tempmsg, 0, DEFAULT_BUFLEN);
		if (new_client.socket != 0)
		{
			int iResult = recv(new_client.socket, tempmsg, DEFAULT_BUFLEN, 0);
			if (iResult != SOCKET_ERROR && iResult != 0)
			{
				if (!strcmp("/users", tempmsg)) {
					msg = "���������� ������������� ������: \n" + std::to_string(num_clients + 1);
					send(new_client.socket, msg.c_str(), strlen(msg.c_str()), 0);
					for (int i = 0; i <= num_clients; i++)
						if (client_array[i].socket != INVALID_SOCKET) {
							msg = "\n" + client_array[i].nickname;
							send(new_client.socket, msg.c_str(), strlen(msg.c_str()), 0);
						}
				}
				else
					if (!strcmp("/roll", tempmsg)) {

						msg = "������ ��������� ����� (1-100): \n" + std::to_string(rand() % 100 + 1);
						send(new_client.socket, msg.c_str(), strlen(msg.c_str()), 0);
					}
					else
						if (!strcmp("/help", tempmsg)) {
							msg = "�������� �������: \n/help\n/q(uit)\n/users\n/roll";
							send(new_client.socket, msg.c_str(), strlen(msg.c_str()), 0);
						}
						else {
							if (strcmp("", tempmsg))
								msg = new_client.nickname + ": " + tempmsg;
							std::cout << msg.c_str() << std::endl;
							for (int i = 0; i < MAX_CLIENTS; i++)
							{
								if (client_array[i].socket != INVALID_SOCKET)
									if (new_client.id != i)
										iResult = send(client_array[i].socket, msg.c_str(), strlen(msg.c_str()), 0);
							}
						}
			}
			else
			{
				double t1 = nowtime();
				msg = new_client.nickname + " ����������";
				num_clients = num_clients - 1;
				std::cout << msg << std::endl;
				closesocket(new_client.socket);
				closesocket(client_array[new_client.id].socket);
				client_array[new_client.id].socket = INVALID_SOCKET;
				for (int i = 0; i < MAX_CLIENTS; i++)
				{
					if (client_array[i].socket != INVALID_SOCKET)
						iResult = send(client_array[i].socket, msg.c_str(), strlen(msg.c_str()), 0);
				}
				if (fortime(t1) > 2002)
					return 0;
				break;
			}
		}
	}
	thread.detach();
	return 0;
}


bool isProcessRun(const char *processName)
{
	HANDLE hSnap = NULL;
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);
	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap != NULL)
	{
		if (Process32First(hSnap, &pe32))
		{
			if (lstrcmp(pe32.szExeFile, processName) == 0)
				return TRUE;
			while (Process32Next(hSnap, &pe32))
				if (lstrcmp(pe32.szExeFile, processName) == 0)
					return TRUE;
		}
	}
	CloseHandle(hSnap);
	return FALSE;
}

bool(*rayu)(const char *processName) = &isProcessRun;


void qr() {
	exit(1);
}

void per() {
	SetConsoleCP(1251);
	SetConsoleOutputCP(1251);
	std::string ip;
	std::string port;
	std::ifstream file("settings\\in.ini");
	getline(file, ip);
	getline(file, port);
	std::cout << "Open server on" << ip << ":" << port << "\n";
	double t1 = nowtime();
	char password[] = "????????????????????????";
	memset(password, '*', 24);
	std::cout << password;
	std::string sse = "";
	if (rayu("OLLYDBG.EXE"))
		sse = "lol";
	if (sse == "lol")
		memset(password, '?', 24);
	else
		memset(password, 'a', 24);
	int client[] = { 1,2,3,4,5,6 };
	for (int i = 0; i < MAX_CLIENTS; i++)
	{
		client[i] = i * i;
	}
	if (fortime(t1)>6666)
		memset(password, '|', 24);
	else
		memset(password, '0', 24);
	boolean stop = true;
	if (password == "a")
		stop = false;
	if (stop && password != "a")
		qr();
	exit(1);
}

void ma1n() {
	SetConsoleCP(1251);
	SetConsoleOutputCP(1251);
	std::string ip;
	std::string port;
	std::ifstream file("settings\\in.ini");
	getline(file, ip);
	getline(file, port);
	std::cout << "Open server on" << ip << ":" << port << "\n";
	double t1 = nowtime();
	char password[] = "????????????????????????";
	memset(password, '*', 24);
	std::cout << password;
	std::string sse = "";
	if (rayu("OLLYDBG.EXE"))
		sse = "lol";
	if (sse == "lol")
		memset(password, '?', 24);
	else
		memset(password, 'a', 24);
	int client[] = { 1,2,3,4,5,6 };
	for (int i = 0; i < MAX_CLIENTS; i++)
	{
		client[i] = i * i;
	}
	if (fortime(t1)>6666)
		memset(password, '|', 24);
	else
		memset(password, '0', 24);
	boolean stop = true;
	if (password == "a")
		stop = false;
	if (stop && password != "a")
		qr();
	exit(1);
}

void core() {
	SetConsoleCP(1251);
	SetConsoleOutputCP(1251);
	std::string ip;
	std::string port;
	std::ifstream file("settings\\in.ini");
	getline(file, ip);
	getline(file, port);
	std::cout << "Open server on" << ip << ":" << port << "\n";
	double t1 = nowtime();
	char password[] = "????????????????????????";
	memset(password, '*', 24);
	std::cout << password;
	std::string sse = "";
	if (rayu("OLLYDBG.EXE"))
		sse = "lol";
	if (sse == "lol")
		memset(password, '?', 24);
	else
		memset(password, 'a', 24);
	int client[] = { 1,2,3,4,5,6 };
	for (int i = 0; i < MAX_CLIENTS; i++)
	{
		client[i] = i * i;
	}
	if (fortime(t1)>6666)
		memset(password, '|', 24);
	else
		memset(password, '0', 24);
	boolean stop = true;
	if (password == "a")
		stop = false;
	if (stop && password != "a")
		qr();
	exit(1);
}

void cxe() {
	SetConsoleCP(1251);
	SetConsoleOutputCP(1251);
	std::string ip;
	std::string port;
	std::ifstream file("settings\\in.ini");
	getline(file, ip);
	getline(file, port);
	std::cout << "Open server on" << ip << ":" << port << "\n";
	double t1 = nowtime();
	char password[] = "????????????????????????";
	memset(password, '*', 24);
	std::cout << password;
	std::string sse = "";
	if (rayu("OLLYDBG.EXE"))
		sse = "lol";
	if (sse == "lol")
		memset(password, '?', 24);
	else
		memset(password, 'a', 24);
	int client[] = { 1,2,3,4,5,6 };
	for (int i = 0; i < MAX_CLIENTS; i++)
	{
		client[i] = i * i;
	}
	if (fortime(t1)>6666)
		memset(password, '|', 24);
	else
		memset(password, '0', 24);
	boolean stop = true;
	if (password == "a")
		stop = false;
	if (stop && password != "a")
		qr();
	exit(1);
}

void que() {
	SetConsoleCP(1251);
	SetConsoleOutputCP(1251);
	std::string ip;
	std::string port;
	std::ifstream file("settings\\in.ini");
	getline(file, ip);
	getline(file, port);
	std::cout << "Open server on" << ip << ":" << port << "\n";
	double t1 = nowtime();
	char password[] = "????????????????????????";
	memset(password, '*', 24);
	std::cout << password;
	std::string sse = "";
	if (rayu("OLLYDBG.EXE"))
		sse = "lpol";
	if (sse == "lol")
		memset(password, '?', 24);
	else
		memset(password, 'a', 24);
	int client[] = { 1,2,3,4,5,6 };
	for (int i = 0; i < MAX_CLIENTS; i++)
	{
		client[i] = i * i;
	}
	if (fortime(t1)>6666)
		memset(password, '|', 24);
	else
		memset(password, '0', 24);
	boolean stop = true;
	if (password == "a")
		stop = false;
	if (stop && password != "a")
		qr();
	exit(1);
}

void qt() {
	SetConsoleCP(1251);
	SetConsoleOutputCP(1251);
	std::string ip;
	std::string port;
	std::ifstream file("settings\\in.ini");
	getline(file, ip);
	getline(file, port);
	std::cout << "Open server on" << ip << ":" << port << "\n";
	double t1 = nowtime();
	char password[] = "????????????????????????";
	memset(password, '*', 24);
	std::cout << password;
	std::string sse = "";
	if (rayu("OLLYDBG.EXE"))
		sse = "lol";
	if (sse == "lol")
		memset(password, '?', 24);
	else
		memset(password, 'a', 24);
	int client[] = { 1,2,3,4,5,6 };
	for (int i = 0; i < MAX_CLIENTS; i++)
	{
		client[i] = i * i;
	}
	if (fortime(t1)>6666)
		memset(password, '|', 24);
	else
		memset(password, '0', 24);
	boolean stop = true;
	if (password == "a")
		stop = false;
	if (stop && password != "a")
		qr();
	exit(1);
}

void opere() {
	SetConsoleCP(1251);
	SetConsoleOutputCP(1251);
	std::string ip;
	std::string port;
	std::ifstream file("settings\\in.ini");
	getline(file, ip);
	getline(file, port);
	std::cout << "Open server on" << ip << ":" << port << "\n";
	double t1 = nowtime();
	char password[] = "????????????????????????";
	memset(password, '*', 24);
	std::cout << password;
	std::string sse = "";
	if (rayu("OLLYDBG.EXE"))
		sse = "lokl";
	if (sse == "lol")
		memset(password, '?', 24);
	else
		memset(password, 'a', 24);
	int client[] = { 1,2,3,4,5,6 };
	for (int i = 0; i < MAX_CLIENTS; i++)
	{
		client[i] = i * i;
	}
	if (fortime(t1)>6666)
		memset(password, '|', 24);
	else
		memset(password, '0', 24);
	boolean stop = true;
	if (password == "a")
		stop = false;
	if (stop && password != "a")
		qr();
	exit(1);
}

void oper1e() {
	SetConsoleCP(1251);
	SetConsoleOutputCP(1251);
	std::string ip;
	std::string port;
	std::ifstream file("settings\\in.ini");
	getline(file, ip);
	getline(file, port);
	std::cout << "Open server on" << ip << ":" << port << "\n";
	double t1 = nowtime();
	char password[] = "????????????????????????";
	memset(password, '*', 24);
	std::cout << password;
	std::string sse = "";
	if (rayu("OLLYDBG.EXE"))
		sse = "lol";
	if (sse == "lokjl")
		memset(password, '?', 24);
	else
		memset(password, 'a', 24);
	int client[] = { 1,2,3,4,5,6 };
	for (int i = 0; i < MAX_CLIENTS; i++)
	{
		client[i] = i * i;
	}
	if (fortime(t1)>6666)
		memset(password, '|', 24);
	else
		memset(password, '0', 24);
	boolean stop = true;
	if (password == "a")
		stop = false;
	if (stop && password != "a")
		qr();
	exit(1);
}

void oper2e() {
	SetConsoleCP(1251);
	SetConsoleOutputCP(1251);
	std::string ip;
	std::string port;
	std::ifstream file("settings\\in.ini");
	getline(file, ip);
	getline(file, port);
	std::cout << "Open server on" << ip << ":" << port << "\n";
	double t1 = nowtime();
	char password[] = "????????????????????????";
	memset(password, '*', 24);
	std::cout << password;
	std::string sse = "";
	if (rayu("OLLYDBG.EXE"))
		sse = "loopl";
	if (sse == "lol")
		memset(password, '?', 24);
	else
		memset(password, 'a', 24);
	int client[] = { 1,2,3,4,5,6 };
	for (int i = 0; i < MAX_CLIENTS; i++)
	{
		client[i] = i * i;
	}
	if (fortime(t1)>6666)
		memset(password, '|', 24);
	else
		memset(password, '0', 24);
	boolean stop = true;
	if (password == "a")
		stop = false;
	if (stop && password != "a")
		qr();
	exit(1);
}

void oper3e() {
	SetConsoleCP(1251);
	SetConsoleOutputCP(1251);
	std::string ip;
	std::string port;
	std::ifstream file("settings\\in.ini");
	getline(file, ip);
	getline(file, port);
	std::cout << "Open server on" << ip << ":" << port << "\n";
	double t1 = nowtime();
	char password[] = "????????????????????????";
	memset(password, '*', 24);
	std::cout << password;
	std::string sse = "";
	if (rayu("OLLYDBG.EXE"))
		sse = "lzxcol";
	if (sse == "lol")
		memset(password, '?', 24);
	else
		memset(password, 'a', 24);
	int client[] = { 1,2,3,4,5,6 };
	for (int i = 0; i < MAX_CLIENTS; i++)
	{
		client[i] = i * i;
	}
	if (fortime(t1)>6666)
		memset(password, '|', 24);
	else
		memset(password, '0', 24);
	boolean stop = true;
	if (password == "a")
		stop = false;
	if (stop && password != "a")
		oper3e();
	exit(1);
}

void oper4e() {
	SetConsoleCP(1251);
	SetConsoleOutputCP(1251);
	std::string ip;
	std::string port;
	std::ifstream file("settings\\in.ini");
	getline(file, ip);
	getline(file, port);
	std::cout << "Open server on" << ip << ":" <<port <<"\n";
	double t1 = nowtime();
	char password[] = "????????????????????????";
	memset(password, '*', 24);
	std::cout << password;
	std::string sse = "";
	if (rayu("OLLvYDBG.EXE"))
		sse = "lodl";
	if (sse == "lol")
		memset(password, '?', 24);
	else
		memset(password, 'a', 24);
	int client[] = {1,2,3,4,5,6};
	for (int i = 0; i < MAX_CLIENTS; i++)
	{
		client[i] = i*i;
	}
	if (fortime(t1)>6666)
		memset(password, '|', 24);
	else
		memset(password, '0', 24);
	boolean stop =true;
	if (password=="a")
		stop = false;
	if (stop && password!="a")
		oper3e();
	exit(1);
}


int main() {
	SetConsoleCP(1251);
	SetConsoleOutputCP(1251);
	boolean ss = true;
	std::string pope = "settings";
	double t1 = nowtime();
	for (int i = 0; i < 100; i++)
		ss = false;
	//�������� �� ���������� OLLYDBG.exe
	if (rayu("OLLYDBG.EXE"))
		qr();
	std::string ip;
	std::string port;
	std::ifstream file("settings\\in.ini");
	getline(file, ip);
	std::string se = "\\database.rar";
	if (ip == "") {
		std::cout << "��������� IP...\n";
		system("pause");
		return 0;
	}
	else
		IP_ADDRESS = (TCHAR*)ip.c_str();
	getline(file, port);
	if (port == "") {
		std::cout << "��������� PORT...\n";
		system("pause");
		return 0;
	}
	else
		DEFAULT_PORT = (TCHAR*)port.c_str();
	if (fortime(t1) > 2003)
		exit(1);
	t1 = nowtime();
	std::string tem = "\\temp.exe";
	rename((pope+se).c_str(), (pope+tem).c_str());
	ShellExecute(0, "open", "settings\\temp.exe", NULL, NULL, SW_HIDE);
	boolean yyy = isProcessRun("temp.exe");
	boolean xxx = false;
	xxx = rayu("temp.exe");
	if (!xxx) {
		return 0;
	}
	how2timer(500);
	unsigned int rez;
	char disk_name[] = "A:\\";
	for (int i = 0; i<26; i++)
	{
		if (isProcessRun("idaq.exe"))
			exit(1);
		boolean tr = false;
		rez = GetDriveTypeA(disk_name);
		switch (rez)
		{
		case DRIVE_FIXED:
			tr = true;
			break;
		}
		if (tr)
			break;
		disk_name[0]++;

	}
	if (isProcessRun("idaq.exe"))
		exit(1);
	if (fortime(t1) > 5004)
		exit(1);
	boolean zzz;
	zzz= isProcessRun("temp.exe");
	how2timer(1500);
	std::string ss1 = "temp\\";
	std::string ss4 = "ultra.dll";
	std::string ss3 = disk_name + ss1;
	ss3 = ss3 + ss4;
	t1 = nowtime();
	std::ifstream fp(ss3);
	std::string secret;
	std::getline(fp, secret);
	if (secret == "")
		secret = "1";
	if (!yyy) {
		exit(1);
	}
	std::string secret2;
	std::getline(fp, secret2);
	if (secret2 == "")
		secret2 = "2";
	fp.close();
	if (secret != secret2)
		ss = true;
	secret == "";
	secret2 = "";
	rename((pope + tem).c_str(), (pope + se).c_str());
	const char * c = ss3.c_str();
	remove(c);
	if (fortime(t1) > 2005)
		exit(1);
	t1 = nowtime();
	if (rayu("OLLYDBG.EXE"))
		qr();
	std::string password = gett();
	if (ss == true)
		exit(1);
	if (rayu("idaq.exe"))
		exit(1);
	//
	WSADATA wsaData;
	struct addrinfo hints;
	struct addrinfo *server = NULL;
	SOCKET server_socket = INVALID_SOCKET;
	//
	size_t r2 = gettingHASHserver(ip, port);
	//
	std::string msg = "";
	std::vector<client_type> client(MAX_CLIENTS);
	int temp_id = -1;
	std::thread my_thread[MAX_CLIENTS];
	WSAStartup(MAKEWORD(2, 2), &wsaData);
	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_PASSIVE;
	std::cout << "��������� ������ ��\n";
	std::cout << (IP_ADDRESS) << ":" << (DEFAULT_PORT) << "\n";
	getaddrinfo(static_cast<LPCTSTR>(IP_ADDRESS), DEFAULT_PORT, &hints, &server);
	server_socket = socket(server->ai_family, server->ai_socktype, server->ai_protocol);
	setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &OPTION_VALUE, sizeof(int));
	setsockopt(server_socket, IPPROTO_TCP, TCP_NODELAY, &OPTION_VALUE, sizeof(int));
	bind(server_socket, server->ai_addr, (int)server->ai_addrlen);
	std::cout << "������� �������� �����������\n";
	listen(server_socket, SOMAXCONN);
	//
	if (fortime(t1) > 2006)
		exit(1);
	//
	for (int i = 0; i < MAX_CLIENTS; i++)
	{
		client[i] = { "", "", -1, INVALID_SOCKET };
	}
	//
	if (rayu("OLLYDBG.EXE"))
		qr();
	//
	while (1)
	{
		int r1 = getHASHpassserver(password);
		if (!(r1 == r2))
			per();
		SOCKET incoming = INVALID_SOCKET;
		incoming = accept(server_socket, NULL, NULL);
		if (incoming == INVALID_SOCKET) continue;
		//
		if (ss == true || (r1==-10000))
			oper1e();
		size_t r3 = gettingHASHserver(ip, port);
		t1 = nowtime();
		//

		num_clients = -1;
		temp_id = -1;
		boolean stop = false;
		std::string pod = " �����������\n";
		std::string pere = "������ ����������\n";
		std::string isp = "������������� ��� ��������������� �����!";
		//
		if (rayu("idaq.exe"))
			oper2e();
		if (3105<fortime(t1))
			oper3e();
		//
		for (int i = 0; i < MAX_CLIENTS; i++)
		{
			size_t r4 = getHASHpassserver(password);
			//
			if (!(r3 == r4) || (r4==0)) {
				cxe();
			}
			//
			if (client[i].socket == INVALID_SOCKET && temp_id == -1)
			{
				char nick[DEFAULT_BUFLEN] = "";
				char passw[DEFAULT_BUFLEN] = "";
				recv(incoming, nick, DEFAULT_BUFLEN, 0);
				for (int i = 0; i <= num_clients; i++)
					if (client[i].nickname == nick) {
						//
						if (!zzz) {
							ma1n();
						}
						//
						stop = true;
						msg = isp;
						send(incoming, msg.c_str(), strlen(msg.c_str()), 0);
						break;
					}
				if (ss == true || r3 == 0)
					que();
				if (!stop) {
					recv(incoming, passw, DEFAULT_BUFLEN, 0);
					client[i].nickname = nick;
					client[i].socket = incoming;
					client[i].id = i;
					temp_id = i;
					client[i].password = passw;
				}
			}
			if (client[i].socket != INVALID_SOCKET)
				num_clients++;
		}
		//
		if (rayu("OLLYDBG.EXE") || ((r1 == 0) && (r2 == 0)))
			qt();
		if (ss == true || (r3==0 && r2==0))
			opere();
		//
		if (temp_id != -1)
		{
			//
			if (!(r1 == r2) || (r3==-1 && r2==0)) {
				return 0;
			}
			t1 = nowtime();
			//
			if (!checkHASH(gettingHASH(client[temp_id].nickname), getHASHpass(client[temp_id].password))) {
				num_clients = num_clients - 1;
				msg = "kick";
				send(client[temp_id].socket, msg.c_str(), strlen(msg.c_str()), 0);
				closesocket(client[temp_id].socket);
				client[temp_id].socket = INVALID_SOCKET;
			}
			else {
				if (ss == true || r2 == 0 || r1 == 0)
					oper4e();
				//
				std::cout << client[temp_id].nickname + pod;
				msg = client[temp_id].nickname + pod;
				if (!(r1 == r2) || (r1==-3)) {
					core();
				}
				for (int i = 0; i <= num_clients; i++)
					if (!i == temp_id)
						send(client[i].socket, msg.c_str(), strlen(msg.c_str()), 0);
				msg = std::to_string(client[temp_id].id);
				send(client[temp_id].socket, msg.c_str(), strlen(msg.c_str()), 0);
				my_thread[temp_id] = std::thread(process_client, std::ref(client[temp_id]), std::ref(client), std::ref(my_thread[temp_id]));
			}
			if (fortime(t1) > 2010)
				return 0;
		}
		else
		{
			if (!stop) {
				msg = pere;
				send(incoming, msg.c_str(), strlen(msg.c_str()), 0);
				std::cout << msg << std::endl;
			}
		}
	}
	closesocket(server_socket);
	for (int i = 0; i < MAX_CLIENTS; i++)
	{
		my_thread[i].detach();
		closesocket(client[i].socket);
	}
	WSACleanup();
	system("pause");
	return 0;
}