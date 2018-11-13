#include <string>
#include <pthreads.h>

void* function(void *ptr)
{
}

int main(int argc, char* argv[])
{
	pthread_t thread;
	int ret = pthread_create(&thread, NULL, function, (void*)0);
	pthread_join(thread, NULL);
	return 0;
}
