# Rhombix Technologies - Cybersecurity Internship Tasks

This repository contains the official implementation of cybersecurity tasks assigned during the Rhombix Technologies Internship.

---

## 🛠️ Task 1: Basic Network Sniffer
A Python-based network analysis tool that captures and parses live network traffic.
* **Features:** Extracts IPv4 packets, identifies protocols (TCP, UDP, ICMP), and displays detailed packet structure.
* **File:** `Network snifferr.py

<img width="505" height="284" alt="(1) sniffer final" src="https://github.com/user-attachments/assets/52f289df-2100-421a-9a8f-e1219362e6bb" />
<img width="499" height="281" alt="(2)sniffer final" src="https://github.com/user-attachments/assets/50810f71-8cdd-44b8-9897-4be421942bc6" />
<img width="385" height="139" alt="(3)sniffer task" src="https://github.com/user-attachments/assets/b2ccbf70-66c5-4353-be52-276c8a4c8bb6" />



## 🔐 Task 2: Advanced Secure File Transfer Application
An enterprise-grade command-line utility designed to guarantee data confidentiality, integrity, and non-repudiation during file operations.

### 🌟 Key Features & Cryptographic Implementation
* **Symmetric Encryption (AES-256-CBC):** Encrypts files using military-grade Advanced Encryption Standard with safe Cipher Block Chaining.
* **Key Derivation (PBKDF2HMAC):** Uses a strong key derivation function with `SHA-256` and 200,000 iterations to stretch passwords into secure cryptographic keys.
* **Data Integrity (HMAC-SHA256):** Generates and verifies an HMAC tag to perform tamper-checking, preventing cipher-text manipulation attacks.
* **Access Control System:** Implements a full user registration and authentication flow with hashed credentials (`SHA-256` with salting).
* **Robust Audit Logging:** Tracks framework events (`FILE_ENCRYPTED`, `INTEGRITY_FAIL`, `LOGIN_OK`, etc.) with accurate formatting and human-readable timestamps.

### 🚀 Setup & Execution
1. Install the required standard security library:
   ```bash
   pip install cryptography
