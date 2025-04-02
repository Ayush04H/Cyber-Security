# Practical Exercises in Python for Cyber Security 🐍🔒

This repository contains Python code for several practical exercises demonstrating concepts in web security, biometric authentication, and password cracking for educational purposes. **Use responsibly and ethically!**

## 1. Basic Web Security Audit Tool 🕸️🛡️

**Approach:** This Python script performs a basic automated web security audit by checking for common security headers, HTTPS usage, `robots.txt`, `sitemap.xml`, basic CMS detection, cookie flags, and common open ports. It uses the `requests` library to fetch web pages and headers, and `socket` for basic port scanning.

**Overview:** The code is structured into functions, each responsible for a specific security check. It outputs results to the console, indicating potential vulnerabilities. This is a rudimentary tool for learning and should not replace professional security audits.

## 2. Fingerprint Biometric Authentication Simulation 🖐️🔑

**Approach:** This Python program simulates a fingerprint biometric authentication process without real sensors. It uses strings and UUIDs to represent fingerprint templates and scans. Enrollment and authentication are simulated through user input and simple string comparison.

**Overview:** The code demonstrates the basic flow of biometric authentication: enrollment and verification. It uses a dictionary to store "fingerprint templates" (UUIDs) and simulates user interaction via the command line. This is a highly simplified model for educational purposes only.

## 4. Offline and Offline Password Cracking (Dictionary Attack) 🗝️ 💻

### Offline Password Cracking (Dictionary Attack) 🗝️ 💻

**Approach:** This Python script demonstrates an offline dictionary attack against password hashes. It reads words from a `dictionary.txt` file, hashes them using SHA256, and compares them to a target password hash.

**Overview:** The code utilizes the `hashlib` library for hashing. It iterates through dictionary words, hashes them, and checks for a match against a provided hash.  This is a basic dictionary attack for educational purposes to understand password cracking principles. **Use ethically and only on hashes you are authorized to test.**

### Online Password Cracking (Dictionary Attack) 🌐 💥

**Approach:** This Python script performs an online dictionary attack against a *locally hosted, vulnerable Flask web application*. It sends HTTP POST requests to the login form with usernames and passwords from a `dictionary.txt` file, checking the server response for successful login indicators.

**Overview:** The code uses the `requests` library to interact with the web application. It simulates form submission and analyzes the HTML response to detect successful logins. This is a *demonstration* against a *local vulnerable app only* to illustrate online attack mechanics. **Unauthorized online password cracking is illegal and unethical. Do not use against live websites without permission.**