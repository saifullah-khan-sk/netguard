# 🛡️ NET-GUARD : A DNS Monitoring Tool for Network Security

This Python-based tool passively monitors network traffic for DNS queries and detects access to **suspicious or malicious domains** in real time. Built using the powerful `scapy` library, it can be used for educational purposes, network auditing, or to enhance security awareness.

## ⚙️ What It Does

- 📡 Captures DNS queries on your network using packet sniffing.
- 🔍 Checks each domain against a list of suspicious or known malicious websites.
- 📁 Logs **all DNS traffic** and raises alerts for **flagged domains**.
- ⏱️ Appends timestamps to all entries for accurate incident tracking.

## 🧪 How It Works

- Uses `scapy` to sniff packets on UDP port 53 (DNS).
- Extracts the domain from each DNS query.
- Compares queried domains to a **custom blacklist**.
- Writes:
  - All queries to `all_traffic.log`
  - Suspicious activity to `security_alerts.log`

## 🏗️ Project Structure

### network_security.py : 
- Main script for monitoring and logging all_traffic.log 
- Auto-generated log of all DNS queries security_alerts.log 
- Auto-generated log for alerts (suspicious domains)

## 🔐 Disclaimer
- This tool is for educational and ethical use only. Do not use it on networks you do not own or have explicit permission to monitor
