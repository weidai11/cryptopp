extern int (*AdhocTest)(int argc, char *argv[]);

int MyAdhocTest(int argc, char *argv[])
{
	return 0;
}

static int s_i = (AdhocTest = &MyAdhocTest, 0);
