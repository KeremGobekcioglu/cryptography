
#include <iostream>
#include <vector>
#include <cstdlib>
#include <ctime>
#include "prime_number_test.c++" // Include the implementation file

using namespace std;

bool testFailed = false;

void customAssert(bool condition, const string &message) {
    if (!condition) {
        cout << "Test failed: " << message << endl;
        testFailed = true;
    }
}

void testModularExponentiation() {
    customAssert(modularExponentiation(2, 3, 5) == 3, "modularExponentiation(2, 3, 5) == 3");
    customAssert(modularExponentiation(2, 5, 13) == 6, "modularExponentiation(2, 5, 13) == 6");
    customAssert(modularExponentiation(3, 4, 7) == 4, "modularExponentiation(3, 4, 7) == 4");
    customAssert(modularExponentiation(0, 0, 5) == 1, "modularExponentiation(0, 0, 5) == 1"); // Edge case
    customAssert(modularExponentiation(0, 5, 5) == 0, "modularExponentiation(0, 5, 5) == 0");
    customAssert(modularExponentiation(5, 0, 7) == 1, "modularExponentiation(5, 0, 7) == 1"); // Anything to the power of 0 is 1
    customAssert(modularExponentiation(7, 2, 1) == 0, "modularExponentiation(7, 2, 1) == 0"); // Mod 1 always results in 0
    customAssert(modularExponentiation(123456789, 123456789, 100000007) == 15470403, "modularExponentiation(123456789, 123456789, 100000007) == 15470403"); // Large test
    cout << "modularExponentiation tests completed.\n";
}

void testMillerRabinTest() {
    customAssert(millerRabinTest(2, 5) == true, "millerRabinTest(2, 5) == true");
    customAssert(millerRabinTest(341, 213) == false, "millerRabinTest(341, 213) == false");
    customAssert(millerRabinTest(3, 5) == true, "millerRabinTest(3, 5) == true");
    customAssert(millerRabinTest(4, 5) == false, "millerRabinTest(4, 5) == false");
    customAssert(millerRabinTest(17, 10) == true, "millerRabinTest(17, 10) == true");
    customAssert(millerRabinTest(18, 5) == false, "millerRabinTest(18, 5) == false");
    customAssert(millerRabinTest(2, 10) == true, "millerRabinTest(2, 10) == true"); // Smallest prime
    customAssert(millerRabinTest(3, 10) == true, "millerRabinTest(3, 10) == true"); // Small prime
    customAssert(millerRabinTest(4, 10) == false, "millerRabinTest(4, 10) == false"); // Small composite
    customAssert(millerRabinTest(10, 10) == false, "millerRabinTest(10, 10) == false"); // Even number
    customAssert(millerRabinTest(10000000019, 20) == true, "millerRabinTest(10000000019, 20) == true"); // Large prime with more iterations
    customAssert(millerRabinTest(10000000019, 10) == true, "millerRabinTest(10000000019, 10) == true"); // Large prime with more iterations
    customAssert(millerRabinTest(10000000018, 20) == false, "millerRabinTest(10000000018, 20) == false"); // Large composite with more iterations
    customAssert(millerRabinTest(-1, 10) == false, "millerRabinTest(-1, 10) == false"); // Negative number
    customAssert(millerRabinTest(0, 10) == false, "millerRabinTest(0, 10) == false"); // Zero
    customAssert(millerRabinTest(1, 10) == false, "millerRabinTest(1, 10) == false"); // One
    cout << "millerRabinTest tests completed.\n";
}

void testSieveOfEratosthenes() {
    vector<int> primes = sieveOfEratosthenes(10);
    vector<int> expected = {2, 3, 5, 7};
    customAssert(primes == expected, "sieveOfEratosthenes(10) == {2, 3, 5, 7}");
    primes = sieveOfEratosthenes(20);
    expected = {2, 3, 5, 7, 11, 13, 17, 19};
    customAssert(primes == expected, "sieveOfEratosthenes(20) == {2, 3, 5, 7, 11, 13, 17, 19}");
    customAssert(sieveOfEratosthenes(0).empty(), "sieveOfEratosthenes(0).empty()");
    customAssert(sieveOfEratosthenes(1).empty(), "sieveOfEratosthenes(1).empty()");
    customAssert(sieveOfEratosthenes(2) == vector<int>{2}, "sieveOfEratosthenes(2) == {2}");
    vector<int> primesUnder50 = {2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47};
    customAssert(sieveOfEratosthenes(50) == primesUnder50, "sieveOfEratosthenes(50) == primesUnder50");
    cout << "sieveOfEratosthenes tests completed.\n";
}

void testSieveOfAtkin() {
    vector<int> primes = sieveOfAtkin(10);
    vector<int> expected = {2, 3, 5, 7};
    customAssert(primes == expected, "sieveOfAtkin(10) == {2, 3, 5, 7}");
    primes = sieveOfAtkin(20);
    expected = {2, 3, 5, 7, 11, 13, 17, 19};
    customAssert(primes == expected, "sieveOfAtkin(20) == {2, 3, 5, 7, 11, 13, 17, 19}");
    customAssert(sieveOfAtkin(0).empty(), "sieveOfAtkin(0).empty()");
    customAssert(sieveOfAtkin(1).empty(), "sieveOfAtkin(1).empty()");
    expected = {2};
    customAssert(sieveOfAtkin(2) == expected, "sieveOfAtkin(2) == {2}");
    expected = {2, 3};
    customAssert(sieveOfAtkin(3) == expected, "sieveOfAtkin(3) == {2, 3}");
    customAssert(sieveOfAtkin(50) == sieveOfEratosthenes(50), "sieveOfAtkin(50) == sieveOfEratosthenes(50)"); // Cross-check with Eratosthenes
    cout << "sieveOfAtkin tests completed.\n";
}

int main() {
    srand(time(0));

    testModularExponentiation();
    testMillerRabinTest();
    testSieveOfEratosthenes();
    testSieveOfAtkin();
    if (testFailed) {
        cout << "Some tests failed.\n";
    } else {
        cout << "All tests passed.\n";
    }
    return 0;
}