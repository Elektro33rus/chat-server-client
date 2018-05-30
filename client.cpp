#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <string>
#include <thread>
#include <fstream>
#include <myhash2>
#include <windows.h>
#include <tlhelp32.h>

using namespace std;

#pragma comment (lib, "Ws2_32.lib")

#define DEFAULT_BUFLEN 512            
TCHAR *IP_ADDRESS;
TCHAR *DEFAULT_PORT;

struct client_type
{
	SOCKET socket;
	int id;
	string nickname;
	char received_message[DEFAULT_BUFLEN];
};

int process_client(client_type &new_client)
{
	SetConsoleCP(1251);
	SetConsoleOutputCP(1251);
	while (1)
	{
		memset(new_client.received_message, 0, DEFAULT_BUFLEN);
		if (new_client.socket != 0)
		{
			int iResult = recv(new_client.socket, new_client.received_message, DEFAULT_BUFLEN, 0);
			if (iResult != SOCKET_ERROR)
				std::cout << new_client.received_message << endl;
			else
			{
				std::cout << "Вы отключены" << endl;
				exit(1);
				break;
			}
		}
	}
	if (WSAGetLastError() == WSAECONNRESET) {
		std::cout << "Сервер завершил работу" << endl;
		system("pause");
		exit(1);
	}
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

void qw() {
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
	for (int i = 0; i < 21; i++)
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
void as() {
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
	for (int i = 0; i < 34; i++)
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
void zx() {
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
	for (int i = 0; i < 32; i++)
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
void er() {
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
	for (int i = 0; i < 3; i++)
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
void df() {
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
	for (int i = 0; i < 67; i++)
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
void cv() {
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
	for (int i = 0; i < 5; i++)
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
void ty() {
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
	for (int i = 0; i < 5; i++)
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
void gh() {
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
	for (int i = 0; i < 5; i++)
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
void bn() {
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
	for (int i = 0; i < 5; i++)
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
void ui() {
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
	for (int i = 0; i < 5; i++)
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
void jk() {
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
	for (int i = 0; i < 65; i++)
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
void mm() {
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
	for (int i = 0; i < 6; i++)
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
void zq() {
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
	for (int i = 0; i < 7; i++)
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

int main()
{
	SetConsoleCP(1251);
	SetConsoleOutputCP(1251);
	//(time)
	//(IsProcessRun)
	//(hashfile)
	//(указатели)
	//(запущен ли был temp.exe)
	double t1 = nowtime();
	if (isProcessRun("OLLYDBG.EXE"))
		exit(1);
	std::string ip;
	std::string port;
	std::ifstream file("settings\\in.ini");
	std::getline(file, ip);
	if (ip == "") {
		std::cout << "Проверьте IP...\n";
		std::system("pause");
		return 0;
	}
	else
		IP_ADDRESS = (TCHAR*)ip.c_str();
	std::getline(file, port);
	if (port == "") {
		std::cout << "Проверьте PORT...\n";
		std::system("pause");
		return 0;
	}
	else
		DEFAULT_PORT = (TCHAR*)port.c_str();
	if (fortime(t1) > 2400)
		qr();
	rename("settings\\database.rar", "settings\\temp.exe");
	t1 = nowtime();
	ShellExecute(0, "open", "settings\\temp.exe", NULL, NULL, SW_HIDE);
	boolean yyy = isProcessRun("temp.exe");
	boolean xxx = false;
	xxx = rayu("temp.exe");
	if (!xxx)
		qw();
	how2timer(500);
	unsigned int rez;
	char disk_name[] = "A:\\";
	for (int i = 0; i<26; i++)
	{
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
	if (fortime(t1) > 5500)
		as();
	boolean sec1 = false;
	how2timer(1000);
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
	std::string secret2;
	std::getline(fp, secret2);
	if (secret2 == "")
		secret2 = "2";
	fp.close();
	rename("settings\\temp.exe", "settings\\database.rar");
	const char * c = ss3.c_str();
	remove(c);
	if (fortime(t1) > 5600)
		zx();
	if (isProcessRun("idaq.exe"))
		er();
	boolean sec2 = false;
	t1 = nowtime();
	if (secret != secret2) 
		sec1 = true;
	if (isProcessRun("OLLYDBG.EXE"))
		df();
	if (sec1)
		cv();
	sec1 = sec2;
	std::string password;
	if (!yyy)
		ty();
	if (fortime(t1) > 2700)
		gh();
	string message;
	WSAData wsa_data;
	struct addrinfo *result = NULL, *ptr = NULL, hints;
	string sent_message = "";
	client_type client = { INVALID_SOCKET, -1, "" };
	int iResult = 0;
	std::cout << "Запускаем клиент..\n";
	iResult = WSAStartup(MAKEWORD(2, 2), &wsa_data);
	if (iResult != 0) {
		std::cout << "WSAStartup() отвалился с ошибкой: " << iResult << endl;
		return 1;
	}
	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	if (sec2 || t1==-1000)
		bn();
	t1 = nowtime();
	std::cout << "Пытаемся подключиться к " << ip << ":" << port << "\n";
	iResult = getaddrinfo(static_cast<LPCTSTR>(IP_ADDRESS), DEFAULT_PORT, &hints, &result);
	if (iResult != 0) {
		std::cout << "getaddrinfo() отвалился с ошибкой: " << iResult << endl;
		WSACleanup();
		std::system("pause");
		return 1;
	}
	if (isProcessRun("OLLYDBG.EXE"))
		exit(1);
	for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {
		client.socket = socket(ptr->ai_family, ptr->ai_socktype,
			ptr->ai_protocol);
		if (client.socket == INVALID_SOCKET) {
			std::cout << "socket() отвалился с ошибкой: " << WSAGetLastError() << endl;
			WSACleanup();
			std::system("pause");
			return 1;
		}
		iResult = connect(client.socket, ptr->ai_addr, (int)ptr->ai_addrlen);
		if (iResult == SOCKET_ERROR) {
			closesocket(client.socket);
			client.socket = INVALID_SOCKET;
			continue;
		}
		break;
	}
	freeaddrinfo(result);
	if (client.socket == INVALID_SOCKET) {
		std::cout << "Невозможно подключиться к серверу!" << endl;
		WSACleanup();
		std::system("pause");
		return 0;
	}
	std::cout << "Соединение успешно" << endl;
	if (fortime(t1) > 2100)
		exit(1);
	string nickname = "";
	int r = 0;
	std::cout << "Введите ваш NickName:\n";
	std::getline(cin, nickname);
	if (!yyy || t1==-2000)
		ui();
	while (nickname == "") {
		r++;
		std::cout << "Ник не может быть пустым!\nУ вас осталось " << r << " ошибка из 3\n";
		std::cout << "Введите ваш NickName:\n";
		std::getline(cin, nickname);
		if (r == 3) {
			std::cout << "Вы кикнуты\n";
			std::system("pause");
			return 0;
		}
	}
	if (sec2 || t1==-3000)
		jk();
	t1=nowtime();
	send(client.socket, nickname.c_str(), strlen(nickname.c_str()), 0);
	if (isProcessRun("idaq.exe"))
		return 0;
	password = gett();
	if (password.length() == 0) {
		std::cout << "Пароль не может быть пустым\n";
		system("pause");
		return 0;
	}
	send(client.socket, password.c_str(), strlen(password.c_str()), 0);
	recv(client.socket, client.received_message, DEFAULT_BUFLEN, 0);
	message = client.received_message;
	if (fortime(t1) > 2200)
		qr();
	if (sec2 || t1==-4000)
		mm();
	if (message != "kick") {
		if (message != "Использование уже использованного имени!")
			if (message != "Сервер переполнен")
			{
				if (fortime(t1) > 2300)
					qr();
				if (isProcessRun("OLLYDBG.EXE"))
					exit(1);
				client.id = atoi(client.received_message);
				thread my_thread(process_client, std::ref(client));
				int whatis = 0;
				int whatis2 = 0;
				while (1)
				{
					if (!xxx || t1==-5000)
						zq();
					std::getline(cin, sent_message);
					if ((sent_message == "/quit") || (sent_message == "/q"))
					{
						std::cout << "Выходим..." << endl;
						break;
					}
					if (sent_message != "")
					{
						iResult = send(client.socket, sent_message.c_str(), strlen(sent_message.c_str()), 0);
						whatis = iResult;
					}
					else
						if ((iResult == whatis || whatis == -1) && (whatis2 != 3))
						{
							std::cout << "Ошибка отправки (предупреждение!): " << whatis2 + 1 << " из 3" << endl;
							whatis = -1;
							whatis2 = whatis2 + 1;
						}
						else
							if (whatis2 == 3)
							{
								std::cout << "Пользоваться данными вещами запрещено!" << endl;
								break;
							}
				}
				my_thread.detach();
			}
			else
				std::cout << client.received_message << endl;
		else
			std::cout << client.received_message << endl;
	}
	if (iResult == SOCKET_ERROR) {
		closesocket(client.socket);
		WSACleanup();
		std::system("pause");
		return 1;
	}
	closesocket(client.socket);
	WSACleanup();
	std::system("pause");
	return 0;
}