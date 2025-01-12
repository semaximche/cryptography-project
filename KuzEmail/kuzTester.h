#include "minunit.h"

#include <iostream>

//Example test checking if variable one has the value 1
MU_TEST(test_example1) {
	std::cout << "Test Running example test 1:" << std::endl;

	//Some code here
	std::cout << "Hello World" << std::endl;

	//Some check here
	mu_check(true);
}

//Example test comparing two strings
MU_TEST(test_example2) {
	std::cout << "Test Running example test 2:" << std::endl;
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