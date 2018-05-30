#include <iostream>
#include <ws2tcpip.h>
#include <string>
#include <fstream>
#include <myhash5>
//C:\Program Files\Microsoft Visual Studio\2017\Community\VC\Tools\MSVC\14.12.25827\include

using namespace std;

int main() {
	SetConsoleCP(1251);
	SetConsoleOutputCP(1251);
	ofstream fout("pass.txt");
	cout << "Введите ваш NickName:\n";
	string nickname = "";
	getline(cin, nickname);
	string ip = "127.0.0.1";
	string port = "27015";
	std::string res1 = "";
	std::string res2 = "";

	res1 = gettingPASSserver(ip, port);
	res2 = gettingPASS(nickname);
	fout << res2 << " :Для логина\n";
	fout << res1 << " :Для сервера\n";
	fout.close();

	system("pause");
	return 0;
}