#include <iostream>
#include <Windows.h>

int
main(
	void
)
{
	MessageBoxW(nullptr, L"Hello", L"TestTarget", MB_OK);
	std::cout << "Hello World!" << std::endl;
}
