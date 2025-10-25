Log Monitoring and Alerting System

## Project Objective
The goal of this project is to design and implement a **Log Monitoring and Alerting System** using Python.  
This script continuously monitors system log entries to detect potential **security threats or anomalies** such as:

- Multiple failed password attempts  
- Suspicious `sudo` authentication activity  
- Malicious keywords like **“malware”**, **“hack”**, or **“attack”**

When a suspicious event is d#etected, the system **immediately generates an alert** in real time and records it in an alert log file for further analysis.

This project demonstrates core cybersecurity concepts including **log analysis, event correlation, and security automation** — without requiring administrative privileges or external dependencies.

---

##  Key Features
-  **Continuous log monitoring** (using file tailing or simulation mode)  
-  **Real-time alerting** for suspicious events  
-  **Keyword scanning** for threat indicators (`malware`, `hack`, `attack`)  
-  **Threshold-based detection** for repeated failed password attempts  
-  **Three operating modes**:
  1. **Simulate mode** – automatically generates sample log data (no files needed)
  2. **FIFO mode** – listens on a named pipe (interactive log feed)
  3. **Logfile mode** – tails any readable log file  
-  **Alert file output** – saves alerts to a local file for evidence or reports  
-  **No external libraries or root access required**

---

## Dependencies / Prerequisites
- Python 3.x (Tested on macOS and Linux)
- No external Python packages required — uses only the standard library.
- Works with any readable log file or via built-in simulation mode.

---

## Setup Instructions

### Clone the Repository
Open your terminal and clone the project from GitHub:
```bash
git clone https://github.com/<evillalazm17>/log_monitor_project.git
cd log_monitor_project
