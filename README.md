# Web Vulnerability Scanner

**Web Vulnerability Scanner** is a Python-based tool designed to identify common security vulnerabilities in web applications. It automates the detection of issues such as SQL injection and Cross-Site Scripting (XSS) by analyzing web pages and their inputs.

## Features

- **Automated Scanning**: Crawls web applications to detect and test input fields for potential vulnerabilities.
- **SQL Injection Detection**: Utilizes a set of SQL payloads to test for SQL injection vulnerabilities.
- **XSS Detection**: Employs a collection of XSS payloads to identify Cross-Site Scripting vulnerabilities.
- **Customizable Payloads**: Allows users to modify or extend the SQL and XSS payload lists to enhance scanning capabilities.

## Requirements

- Python 3.x
- Libraries specified in `requirements.txt`

## Installation

1. **Clone the Repository**:

   ```bash
   git clone https://github.com/Babun9348/web_vuln_scanner.git
   ```


2. **Navigate to the Project Directory**:

   ```bash
   cd web_vuln_scanner
   ```


3. **Install Required Dependencies**:

   ```bash
   pip install -r requirements.txt
   ```


## Usage

1. **Run the Scanner**:

   ```bash
   python webvuln_scanner.py <target_url>
   ```


   Replace `<target_url>` with the URL of the web application you wish to scan.

2. **Review Results**:

   The scanner will output any detected vulnerabilities directly to the console.

## Payload Files

- **`sql_payload.txt`**: Contains SQL injection payloads used during scanning.
- **`xss_payload.txt`**: Contains XSS payloads used during scanning.

You can customize these files to add or modify payloads as needed.

## Disclaimer

This tool is intended for educational purposes and authorized testing only. Unauthorized use against systems without explicit permission is illegal and unethical. The developers are not responsible for any misuse or damage caused by this tool.

## License

This project is licensed under the [MIT License](LICENSE).

---

*Note: This README is based on the available information from the repository. For more detailed instructions and updates, please refer to the source code and comments within the scripts.* 
