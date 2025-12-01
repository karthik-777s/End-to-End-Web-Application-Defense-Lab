Project overview
This project is a hands-on web application defense lab that integrates SafeLine WAF, Snort IDS, Wazuh, Splunk, and DVWA to simulate real-world attacks and end-to-end detection. The goal is to show how multiple security layers (WAF, IDS, HIDS, SIEM) work together to protect a deliberately vulnerable web application while giving blue-team style visibility across the full attack path. DVWA serves as the intentionally vulnerable target application, allowing safe practice of common web attack techniques in a controlled environment.​

Architecture summary
The lab is built around a simple network where an attacker or test client sends HTTP requests through the Internet to a SafeLine WAF that fronts a web server running DVWA and the Wazuh agent. Snort is positioned to monitor the traffic between the WAF and the DVWA server, while Wazuh collects host-level events and forwards them, together with Snort and WAF logs, to Splunk for centralized analysis and dashboards. The provided architecture diagram illustrates this flow from attacker to WAF, IDS, host agent, Wazuh Manager, and finally into Splunk SIEM.​

<img width="2400" height="1600" alt="Architecture_diagram_of_an_integrated_web_security_lab_using_SafeLine_WAF,_Snort,_Wazuh,_DVWA,_and_Splunk" src="https://github.com/user-attachments/assets/4e4628e6-864d-4d38-ad32-b1f408b2599a" />


DVWA (Damn Vulnerable Web Application): A deliberately insecure PHP/MySQL application used to practice exploiting OWASP-style vulnerabilities such as SQL injection, XSS, command injection, and more. In this lab it runs on a web server behind the WAF and is the primary attack target.​

SafeLine WAF: An open-source web application firewall that inspects HTTP(S) traffic, blocks or challenges attacks, and generates detailed web attack logs that are later forwarded for security monitoring. SafeLine is configured to protect the DVWA virtual host and to log detection events that can be consumed by Wazuh and Splunk.​

Snort IDS: A network intrusion detection sensor deployed on the DVWA segment to monitor HTTP traffic coming through the WAF, using rules to detect signatures of web attacks such as those demonstrated against DVWA. Snort generates alert logs that are shipped into Wazuh and optionally directly into Splunk for network-layer visibility.​

Wazuh: A host-based intrusion detection and security monitoring platform where agents installed on servers collect OS, application, and security logs and send them to a central Wazuh Manager for analysis. In this lab, Wazuh ingests logs from the DVWA server (and optionally SafeLine) and can also parse and enrich Snort and WAF alerts for correlation and automated response.​

Splunk: A SIEM platform used here as the central analytics and visualization layer, receiving events from Wazuh (via a Splunk Universal Forwarder or similar integration) and, optionally, direct feeds from Snort and SafeLine. Splunk indexes these logs so that you can build searches, dashboards, and alerts that show the full kill chain from initial request to detection and response.​

Key features and learning goals
End-to-end attack visibility: Launch attacks against DVWA (SQLi, XSS, command injection, etc.) and observe how they appear as WAF detections, Snort IDS alerts, Wazuh host events, and correlated Splunk dashboards. This helps build intuition on how different security layers see the same attack from different perspectives.​

Multi-layer defense design: Practice designing and tuning a layered defense where WAF rules, Snort signatures, and Wazuh decoders/rules work together instead of in isolation. This mirrors modern SOC practices that combine endpoint, network, and application telemetry in a central SIEM for faster detection and investigation.​

Log integration and parsing: Learn how to forward logs from SafeLine, Snort, and Wazuh into Splunk, configure inputs, and apply field extractions so that critical metadata (source IP, URL, rule ID, etc.) is queryable. This provides hands-on experience with SIEM data onboarding, which is a key skill in security operations roles.​

Use-case and dashboard development: Build Splunk searches and dashboards that answer questions like “which IPs triggered the most WAF alerts,” “which DVWA vulnerabilities are being exploited,” and “how many Snort and Wazuh alerts correlate to a single attack campaign.” These use cases can be highlighted in your portfolio to demonstrate practical detection engineering and SOC-style analysis.​

How to use this lab
In a typical workflow, you start the lab services (SafeLine WAF, DVWA web server with Wazuh agent, Snort sensor, Wazuh Manager, and Splunk) and confirm that logs are flowing into Wazuh and Splunk. You then run different attack scenarios against DVWA from a test machine, such as exploiting SQL injection or XSS, and observe how each layer (WAF, IDS, HIDS, SIEM) records and surfaces the activity. Finally, you tune rules, add new detections, and refine dashboards to reduce noise and highlight the most important security events, effectively simulating how a small SOC would monitor and defend a vulnerable web application in real time
