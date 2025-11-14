🐞 CodeAlpha Bug Bounty Automation Tool

Automated Bug Bounty Scanner developed as part of the CodeAlpha Cybersecurity Internship (Task 1).
This tool performs basic vulnerability checks, security header analysis, directory brute-forcing, port scanning, and simple XSS/SQLi heuristic tests.

📌 Project Overview

This project focuses on automating common bug bounty reconnaissance steps using Python.
It scans a target URL for potential weaknesses by checking:

Missing security headers

Open ports

Sensitive directories

robots.txt exposure

Basic reflected XSS possibility

Basic SQL injection indicators

Links extracted from homepage

It generates both TXT and JSON formatted reports, making it useful for learning and documenting security issues.

🚀 Features

✔ Security header scanner
✔ Directory brute-force (small common wordlist)
✔ Basic XSS reflection test
✔ Basic SQLi heuristic test
✔ robots.txt inspection
✔ Homepage link extraction
✔ Open port scanning (common ports)
✔ Auto-generated report files (.txt and .json)

🛠 Technologies Used

Python 3

requests

socket

beautifulsoup4

Standard Python libraries

📂 Files in This Repository

bug_bounty_tool.py → Main tool script

report_.txt / report_.json → Sample reports

screenshot.png → Screenshot of output (optional)

README.md → Project documentation

LICENSE → MIT License

📦 Installation

Clone the repository:

git clone https://github.com/AbbasKamal403/CodeAlpha_BugBountyTool.git
cd CodeAlpha_BugBountyTool


Install dependencies:

pip install requests beautifulsoup4

▶️ Usage

Run the tool:

python3 bug_bounty_tool.py <target-url>


Example:

python3 bug_bounty_tool.py http://testphp.vulnweb.com


Reports will be saved automatically.

📸 Sample Output

(Add your screenshot here)

[+] Starting scan...
[*] Scanning security headers...
[*] Running XSS test...
[*] Checking robots.txt...
[+] Report saved as report_example.txt

📝 Disclaimer

This tool is created strictly for educational purposes during the CodeAlpha Cybersecurity Internship.
🔒 Use only on websites you own or have explicit permission to test.

📧 Contact

👤 Abbas Kamal
GitHub: AbbasKamal403

Email: abbaskamal403@gmail.com
