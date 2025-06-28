# 🔐 Encrypted File Vault System (C++)

This is a highly secure file storage system built in C++ designed for critical data protection on Linux systems, featuring advanced encryption, access controls, and anomaly detection.

## ✨ Features
- 🛡️ AES-256 / ChaCha20 encryption with secure key management  
- 🔑 OTP-protected file access via email alerts for enhanced security  
- 🧑‍💻 Role-based access (Admin, Editor, Viewer) to manage user permissions  
- 🔄 File versioning & audit trail for integrity and recovery  
- 📁 Recursive folder uploads leveraging C++17 `std::filesystem`  
- 📊 Python-based anomaly detection during login events  
- 🧠 Suspicious login pattern alerts via pandas and time-based rules  
- 🔒 Admin panel for access revocation, password resets, and user management  

## 📁 Project Structure
```
EncryptedFileVault/
├── vault_system.cpp           # Main C++ backend (vault logic, user roles, encryption)
├── detect_anomalies.py        # Python script for behavioral anomaly detection
├── README.md                  # This file
├── /data/                     # User files, logs, versions (auto-created directory)
└── /users/                    # Encrypted user database & roles
```

## 🛠️ Technologies
- **C++17**: Core application logic and file system interactions  
- **OpenSSL**: For robust AES and RSA encryption  
- **Mailutils**: For sending email notifications (e.g., OTPs)  
- **Python**:  
  - `pandas`: Data analysis for anomaly detection  
  - `datetime`: Time-based rule enforcement  
  - `smtplib`: Email communication for alerts  
- **Bash**: Scripting for automation and system integration (e.g., cron jobs)  
- **Linux/Kali Terminal**: Primary command-line interface for interaction  

## 💡 What Makes It Unique?
Unlike traditional file lockers, this system integrates live anomaly detection, OTP verification over email, and admin-level monitoring, all running in a native Linux environment. This combination provides low-level control with intelligent access security, setting it apart from standard solutions.

## 🚀 Getting Started
To compile and run the system, use the following commands in your Linux terminal:

```
bash
g++ -std=c++17 -o vault_system vault_system.cpp -lssl -lcrypto
./vault_system
🔐 Note: Use a Gmail App Password when prompted for email authentication.
```

## 👥 Contributors
```
Ishmeet Singh Arora – Core development, C++ backend, anomaly detection pipeline, secure communication features
```
## 🔭 Future Scope
```
- 🖼️ Full Qt-based GUI integration for enhanced usability and a modern interface
- ☁️ Cloud sync for secure file backup and distributed storage
- 🧠 Machine Learning model for advanced intrusion detection (e.g., clustering login patterns) to improve predictive capabilities
- 🧾 Encrypted logs and blockchain-based file integrity validation for immutable audit trails and enhanced data trust
```
