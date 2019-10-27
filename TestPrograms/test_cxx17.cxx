#include <exception>
int main(int argc, char* argv[])
{
	return 0 == std::uncaught_exceptions() ? 0 : 1;
}