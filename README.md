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

   ##Run the application:
   python securee file.py
   ## Demo video:
   you can watch the working in the video:
   https://www.linkedin.com/posts/maryam-mansha-0567b83a6_cybersecurity-cryptography-pythonprogramming-ugcPost-7462949701160570880-h_Za/?utm_source=share&utm_medium=member_desktop&rcm=ACoAAGNuJUIB1omOnhHs-7PIIK1bh41h1z1FGmc
   



## 🔒 Task 3: RFID Core Access Control & Blocking System

A robust, Command-Line Interface (CLI) based **RFID Access Control and Management System** developed in Python. This security application focuses on Identity and Access Management (IAM) principles, simulating real-time authentication, dynamic card state management (blacklisting/whitelisting), and strict data logging using local CSV file handling.

### 🚀 Key Features
* **Identity Verification & IAM Simulation:** Categorizes incoming scans into three distinct operational states:
  * `ALLOWED`: Instantly verifies active registered identities.
  * `BLOCKED`: Denies unauthorized entry attempts from lost or blacklisted cards.
  * `SUSPICIOUS`: Automatically flags unknown or rogue credentials for review.
* **Persistent Data Infrastructure:** Uses local `CSV` structures (`registered_cards.csv`, `blocked_cards.csv`) to handle real-time configurations without requiring an external database.
* **Dynamic Configuration & Governance:** Complete admin controls to register new identities, remove active credentials, or toggle live security blocking rules on demand.
* **Security Auditing & Logs:** Generates a tamper-evident, persistent scan log (`scan_log.csv`) complete with precise ISO-style timestamps for comprehensive compliance tracking.

---

### ⚙️ Core Logic Flow

1. **Card Scan Detection:** Accepts a manual keyboard input string or triggers an automated random generator to mimic an RFID physical tap.
2. **Blacklist Validation:** Cross-references the unique credential against the blocked cache file first.
3. **Authorization Check:** Evaluates active user status within the whitelisted registration system if it bypasses the blacklist check.
4. **Audit Generation:** Appends the final evaluation result and transaction history straight into the centralized logger.

5. 💻 System Execution Documentation:
6. ## 💻 How to Run

1. 
   ```bash
   python Rhombix task 3 RFID blocking.py

   ##Demo video:
   You can watch the working in the video:
   https://www.linkedin.com/posts/maryam-mansha-0567b83a6_cybersecurity-python-iam-ugcPost-7473087042759901185-zcoF/?utm_source=share&utm_medium=member_desktop&rcm=ACoAAGNuJUIB1omOnhHs-7PIIK1bh41h1z1FGmc
   
   

   
