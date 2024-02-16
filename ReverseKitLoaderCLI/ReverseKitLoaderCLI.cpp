#include "ReverseKitLoaderCLI.h"

std::string ProcessName;
std::string DLLName = "ReverseKit.dll";
DWORD ProcessID = 0;

static void clrscr()
{
	// https://stackoverflow.com/questions/17335816/clear-screen-using-c
	std::cout << "\033[2J\033[1;1H";
}

static void pausescr()
{
	// https://www.delftstack.com/howto/cpp/how-to-pause-a-program-in-cpp/
	int nFlag = getc(stdin);
}

int main()
{
	if (!PathFileExistsA(DLLName.c_str()))
	{
		printf("Error: ReverseKit.dll not found\n");
		pausescr();
		return 0;
	}

	printf("Process Name: ");

	std::cin >> ProcessName;

	clrscr();

	printf("Waiting for process to start...\n");

	while (!ProcessID)
		ProcessID = ReverseKitLoader::GetProcessID(ProcessName.c_str());

	if (!ReverseKitLoader::LoadDLL(ProcessID, DLLName.c_str()))
	{
		printf("Error: Failed to inject\n");
		pausescr();
	}
	return 0;
}