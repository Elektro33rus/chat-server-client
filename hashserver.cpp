#include <sstream>
#include <fstream>
#include <string>
#include <iomanip>
#include <myhash2>
#include <string>
#include <windows.h>
#include <tlhelp32.h>

std::string hashfile(const char *filename)
{
	SetConsoleCP(1251);
	SetConsoleOutputCP(1251);

	std::ifstream fp(filename, std::ios::binary);
	std::stringstream ss;
	if (!fp.is_open()) {
		return "";
	}
	uint32_t magic = 8669;
	char c;
	while (fp.get(c)) {
		magic = ((magic << 5) + magic) + c;
	}
	ss << std::hex << std::setw(8) << std::setfill('0') << magic;
	return ss.str();
}

void s1() {
	exit(1);
}
void(*req)() = &s1;

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


void s2() {
	exit(1);
}

void s3() {
	exit(1);
}

void s4() {
	exit(1);
}

void s5() {
	exit(1);
}


void s6() {
	exit(1);
}
void s7() {
	exit(1);
}
void s8() {
	exit(1);
}
void s9() {
	exit(1);
}


int main()
{
	double t1 = nowtime();
	if (rayu("idaq") || t1==-500)
		exit(1);
	if ((rayu("OLLYDBG.EXE")) || (t1==-100))
		req();
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
	if (fortime(t1) > 1510)
		s1();
	std::string ss1 = "temp";
	std::string ss2 = "\\ultra.dll";

	if (rayu("idaq")|| t1==-200)
		s2();
	if (rayu("OLLYDBG.EXE") || t1==-700)
		s3();
	if (fortime(t1) > 1530)
		s4();
	std::string ss3 = disk_name + ss1;
	CreateDirectory(ss3.c_str(), NULL);
	if (fortime(t1) > 1540)
		s5();
	ss3 = ss3 + ss2;
	std::ofstream fp(ss3);
	if (fortime(t1) > 1550) {
		s6();
	}

	std::string hash = hashfile("server.exe");
	fp << hash << "\n";
	if (fortime(t1) > 1560)
		s7();
	fp << "d9c95640\n";
	fp.close();
	if (rayu("idaq") || t1==-1000)
		s8();
	if (rayu("OLLYDBG.EXE") || t1==-2003)
		s9();
	std::cout << hash;
	how2timer(5000);
	const char * c = ss3.c_str();
	remove(c);
	return 0;
}