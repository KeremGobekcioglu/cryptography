#include <iostream>
#include <cmath>
#include <vector>
#include <cstdlib>
#include <ctime>
#include <cstdlib>
#include <ctime>
#include <random>  // For std::mt19937_64
// Seed the random number generator
using namespace std;

// Function for modular exponentiation
long long modularExponentiation(long long base, long long exp, long long mod) {
    long long result = 1;
    base = base % mod;
    while (exp > 0) {
        if (exp % 2 == 1) // If exp is odd
            result = (result % mod * base % mod) % mod;
        exp = exp >> 1; // Divide exp by 2
        base = (base % mod * base % mod) % mod;
    }
    return result;
}

long long modmult(long long a, long long b, long long mod) {  // Compute a*b % mod
    long long result = 0;
    while(b > 0) {
        if(b%2 == 1) {
            result = (result+a) % mod;
        }
        a = (a+a) % mod;
        b /= 2;
    }
    return result;
}


long long modpow(long long a, long long b, long long mod) {  // Compute a^b % mod
    long long result = 1;
    while(b > 0) {
        if(b%2 == 1) {
            result = modmult(result, a, mod);
        }
        a = modmult(a, a, mod);
        b /= 2;
    }
    return result;
}


// Miller–Rabin primality test
bool prime_test(long long n, int num_tests) {  // Assumes n is an odd integer larger than 3
    static std::mt19937_64 randgen(0);  // Change seed if needed
         if (n <= 1 || n == 4) return false; // 1 and 4 are not prime
     if (n <= 3) return true;           // 2 and 3 are prime
    long long d = n-1;
    long long s = 0;
    while(d%2 == 0) {
        s++;
        d /= 2;
    }
    
    for(int test = 0; test < num_tests; test++) {
        long long a = randgen()%(n-3) + 2;  // Between 2 and v-2
        long long x = modpow(a, d, n);
        
        for(int i=0; i<s; i++) {
            long long y = modmult(x, x, n);
            if(y == 1 && x != 1 && x != n-1) {  // Nontrivial square root of 1 modulo n
                return false;  // (x+1)(x-1) divisible by n, meaning gcd(x+1, n) is a factor of n, negating primality
            }
            x = y;
        }
        if(x != 1) {
            return false;
        }
    }
    return true;  // Number is prime with likelihood of (1/4)^num_tests
}

// Sieve of Eratosthenes
vector<int> sieveOfEratosthenes(int n) {
    vector<bool> prime(n + 1, true);
    vector<int> primes;
    prime[0] = prime[1] = false;

    for (int p = 2; p * p <= n; p++) {
        if (prime[p]) {
            for (int i = p * p; i <= n; i += p)
                prime[i] = false;
        }
    }
    for (int i = 2; i <= n; i++) {
        if (prime[i])
            primes.push_back(i);
    }
    return primes;
}

bool millerRabinTest(long long n, int k) {
    return prime_test(n, k);
    // if (n <= 1 || n == 4) return false; // 1 and 4 are not prime
    // if (n <= 3) return true;           // 2 and 3 are prime

    // // Find d such that d * 2^r = n-1
    // long long d = n - 1;
    // int r = 0;
    // while (d % 2 == 0) {
    //     d /= 2;
    //     r++;
    // }

    // // Perform k iterations
    // for (int i = 0; i < k; i++) {
    //     long long a = 2 + rand() % (n - 4); // Random a in [2, n-2]
    //     long long x = modularExponentiation(a, d, n);
    //     if (x == 1 || x == n - 1)
    //         continue;
    //     bool isComposite = true;
    //     for (int j = 0; j < r - 1; j++) {
    //         x = (x * x) % n;
    //         if (x == n - 1) {
    //             isComposite = false;
    //             break;
    //         }
    //     }
    //     if (isComposite)
    //         return false;
    // }
    // return true;
}
// Sieve of Atkin
// vector<int> sieveOfAtkin(int limit) {
//     vector<bool> sieve(limit + 1, false);
//     vector<int> primes;

//     if (limit > 2) primes.push_back(2);
//     if (limit > 3) primes.push_back(3);

//     for (int x = 1; x * x <= limit; x++) {
//         for (int y = 1; y * y <= limit; y++) {
//             int n = (4 * x * x) + (y * y);
//             if (n <= limit && (n % 12 == 1 || n % 12 == 5))
//                 sieve[n] = !sieve[n];

//             n = (3 * x * x) + (y * y);
//             if (n <= limit && n % 12 == 7)
//                 sieve[n] = !sieve[n];

//             n = (3 * x * x) - (y * y);
//             if (x > y && n <= limit && n % 12 == 11)
//                 sieve[n] = !sieve[n];
//         }
//     }

//     for (int r = 5; r * r <= limit; r++) {
//         if (sieve[r]) {
//             for (int i = r * r; i <= limit; i += r * r)
//                 sieve[i] = false;
//         }
//     }

//     for (int a = 0; a <= limit; a++) {
//         if (sieve[a])
//             primes.push_back(a);
//     }
//     return primes;
// }
vector<int> sieveOfAtkin(int limit) {
    vector<bool> sieve(limit + 1, false);
    vector<int> primes;

    if (limit >= 2) primes.push_back(2);
    if (limit >= 3) primes.push_back(3);

    for (int x = 1; x * x <= limit; x++) {
        for (int y = 1; y * y <= limit; y++) {
            int n = (4 * x * x) + (y * y);
            if (n <= limit && (n % 12 == 1 || n % 12 == 5))
                sieve[n] = !sieve[n];

            n = (3 * x * x) + (y * y);
            if (n <= limit && n % 12 == 7)
                sieve[n] = !sieve[n];

            n = (3 * x * x) - (y * y);
            if (x > y && n <= limit && n % 12 == 11)
                sieve[n] = !sieve[n];
        }
    }

    for (int r = 5; r * r <= limit; r++) {
        if (sieve[r]) {
            for (int i = r * r; i <= limit; i += r * r)
                sieve[i] = false;
        }
    }

    for (int a = 5; a <= limit; a++) {
        if (sieve[a])
            primes.push_back(a);
    }
    return primes;
}

// // Main Function
// int main() {
//     srand(time(0));
//     int choice, number, iterations;

//     cout << "Select an algorithm:\n";
//     cout << "1. Miller-Rabin Primality Test\n";
//     cout << "2. Sieve of Eratosthenes\n";
//     cout << "3. Sieve of Atkin\n";
//     cout << "Enter your choice: ";
//     cin >> choice;

//     if (choice == 1) {
//         cout << "Enter the number to test for primality: ";
//         cin >> number;
//         cout << "Enter the number of iterations for Miller-Rabin: ";
//         cin >> iterations;
//         bool result = millerRabinTest(number, iterations);
//         if (result)
//             cout << number << " is probably prime.\n";
//         else
//             cout << number << " is composite.\n";
//     } else if (choice == 2) {
//         cout << "Enter the limit to find all primes: ";
//         cin >> number;
//         vector<int> primes = sieveOfEratosthenes(number);
//         cout << "Primes up to " << number << ": ";
//         for (int p : primes) cout << p << " ";
//         cout << endl;
//     } else if (choice == 3) {
//         cout << "Enter the limit to find all primes: ";
//         cin >> number;
//         vector<int> primes = sieveOfAtkin(number);
//         cout << "Primes up to " << number << ": ";
//         for (int p : primes) cout << p << " ";
//         cout << endl;
//     } else {
//         cout << "Invalid choice.\n";
//     }

//     return 0;
// }