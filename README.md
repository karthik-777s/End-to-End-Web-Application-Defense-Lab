# Project Guardian: Multi-Layer Web Attack Detection & Defense Lab

This repository contains a hands-on web application defense lab that integrates **SafeLine WAF**, **Snort IDS**, **Wazuh**, **Splunk**, and **DVWA** to simulate real-world web attacks and monitor them end-to-end. The lab demonstrates how multiple security layers (WAF, IDS, HIDS, SIEM) work together to protect a deliberately vulnerable web application and provide blue-team style visibility across the full attack path.

---

## Architecture

The lab is built around a simple network:

- An **Attacker / Test Client** sends HTTP requests (including intentional attacks) towards the lab.
- Traffic flows through the **Internet** and hits **SafeLine WAF**, which inspects and filters malicious web requests.
- Behind the WAF, **Snort IDS** monitors the HTTP traffic going to the web server.
- The **Web Server** hosts **DVWA (Damn Vulnerable Web Application)** and runs a **Wazuh Agent** to collect host and application logs.
- A central **Wazuh Manager / Server** receives events from the Wazuh Agent and Snort.
- **Splunk SIEM** ingests events from Wazuh (and optionally directly from SafeLine WAF and Snort) to provide centralized search, dashboards, and alerting.

You can represent the architecture with a diagram like this (save your diagram as `architecture.png` and place it in the repo):

