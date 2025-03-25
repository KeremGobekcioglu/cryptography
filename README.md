# Lightweight Encryption and Prime Number Verification Suite

This project implements a two-part cryptographic system focused on:

1. 🔍 **Prime Number Testing and Verification** using Miller-Rabin and related methods.
2. 🔐 **Lightweight Authenticated Encryption** algorithms including **ISAP** and **Elephant** — efficient and secure choices for constrained environments.

It combines theoretical cryptography research and practical Python implementations.

---

## 📁 Project Structure

- `prime-number-testing/`:  
  Implementation of the **Miller-Rabin** primality test, input/output handling, and number generation.
  
- `lightweight-encryption/`:  
  AEAD implementations of **ISAP** and **Elephant**, including S-box operations, permutation layers, and test cases.

---

## 🧪 Research Background

This work is supported by references to cutting-edge cryptographic literature, including but not limited to:

- ISAP and Elephant official specifications
- NIST's Post-Quantum Cryptography standards
- Prime number testing algorithms from academic sources

For full references and explanations, see the accompanying report below.

---

## 📄 Project Report

🧾 **[Lightweight Encryption and Post-Quantum Cryptography (PDF)](./Lightweight%20Encryption%20and%20Post-Quantum%20Cryptography.pdf)**

The report contains:
- Theory and analysis of each algorithm
- Implementation notes
- Benchmark results
- Research references

---

## 📝 License

This project is licensed under the **MIT License**.  
See [`LICENSE`](./LICENSE) for details.

---

## 🙏 Acknowledgments

Special thanks to the authors of the ISAP and Elephant specifications, and to the broader cryptographic research community that contributed tools, theory, and documentation referenced in this work.
