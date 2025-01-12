#include "minunit.h"

//Example test checking if variable one has the value 1
MU_TEST(test_example1) {
	int one = 1;
	mu_check(one == 1);
}

//Example test comparing two strings
MU_TEST(test_example2) {
	char one[] = "Hello";
	char two[] = "Heoo";
	mu_check(one == two);
}

//Example test suite containing the above 2 unit tests
MU_TEST_SUITE(test_suite_example) {
	MU_RUN_TEST(test_example1);
	MU_RUN_TEST(test_example2);
}

//Add more tests and test suites here....

class KuzTester {
public:
	static bool RunTests() {
		//Run test suites, add more suites to run here...
		MU_RUN_SUITE(test_suite_example);

		//Report and exit
		MU_REPORT();
		return MU_EXIT_CODE;
	}
};