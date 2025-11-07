# MedCare App — Secure Doctor Appointment Slot Booking System

### Overview

The **MedCare App** is a web-based doctor appointment slot booking system built with **Flask**, designed to allow patients to conveniently schedule appointments with doctors through a secure online platform.
It was developed as an enhanced version of an existing open-source system, focusing on **improving functionality, usability, and security**.

This version implements comprehensive **security mechanisms** including:

* Role-Based Access Control (RBAC)
* Two-Factor Authentication (2FA)
* Input validation and sanitization
* Data encryption and password hashing
* HTTPS with TLS 1.3
* Logging and analytics dashboard
* Automated vulnerability and dependency scanning

---

### User Roles and Features

#### **Admin**

* Manage doctors (add/delete)
* View and monitor patient appointments
* Access full system logs and analytics dashboard

#### **Doctor**

* View assigned appointments
* Approve or reject patient booking requests

#### **Patient**

* Register an account
* Book, view, and cancel appointments
* Change password securely

---

### Security Features

* **AES-based field encryption** for phone numbers
* **PBKDF2 with SHA-256** password hashing
* **Role-Based Access Control (RBAC)**
* **2FA (Two-Factor Authentication)** via Google or Microsoft Authenticator
* **Session timeout management** (auto-logout after 30 minutes of inactivity)
* **Rate limiting** to prevent brute-force attacks
* **Secure and HttpOnly cookies** to prevent XSS and session hijacking
* **HTTPS (TLS 1.3)** communication
* **Input validation and sanitization** using `bleach` and parameterized SQL queries
* **Logging and analytics dashboard** for admin auditing
* **Security Tips page** to promote user awareness

---

### System Requirements

* **Python** 3.10+
* **Flask** 3.x
* **SQLite3** (default database)
* **Virtual environment** recommended

---

### Installation Guide

#### Clone the repository

git clone https://github.com/poohbae/SlotBookingSystem.git
cd MedCare-App

#### 2. Create and activate a virtual environment

python -m venv venv
source venv/bin/activate      # For macOS/Linux
venv\Scripts\activate         # For Windows

#### 3. Install dependencies

pip install -r requirements.txt

#### 4. Generate SSL certificates for HTTPS (optional for local testing)

openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes

#### 5. Run the application

python app.py
Then open: [https://127.0.0.1:5000](https://127.0.0.1:5000)

---

### Security Testing

The system underwent multiple security assessments:

* **Nikto** – Automated vulnerability scanning
* **Bandit** – Static code analysis
* **Safety CLI** – Dependency CVE check

All results confirmed **no critical vulnerabilities** and full compliance with **OWASP Top 10** guidelines.

---

### Logging & Analytics

* Real-time tracking of user activities
* Role-based access to logs
* Downloadable CSV export for auditing

---

### Contributors

| Name           | ID       | Role                                                  |
| -------------- | -------- | ----------------------------------------------------- |
| Amelia         | 15095639 | Access Control, Authentication & Secure Communication |
| Chong Kai Juan | 15095673 | Input Validation & Security Testing                   |
| Law Wei Ming   | 15095776 | Logging & User Education                              |

---