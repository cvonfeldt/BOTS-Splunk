# 01 - Boss of the SOC (BOTS) v1 - Website Defacement Investigation

## Overview
This documents an investigation into a website defacement attack against imreallynotbatman.com, a Wayne Enterprises web property. The attack was carried out by the threat actor group Po1s0n1vy. All activity was investigated using Splunk with data sources including Suricata IDS, Fortigate firewall, stream:http, and Sysmon logs.

## Lab Environment

| Role | Details |
|------|---------|
| SIEM | Splunk (BOTS v1 dataset) |
| Target | imreallynotbatman.com (192.168.250.70) |
| Attacker (scanner/brute force) | 40.80.148.42 |
| Attacker (hosting infrastructure) | 23.22.63.114 |

**Data Sources Used:** Suricata, Fortigate (fgt_utm), stream:http, WinEventLog:Security, XmlWinEventLog:Microsoft-Windows-Sysmon/Operational

## Investigation

### Q1: What is the likely IPv4 address of someone from the Po1s0n1vy group scanning imreallynotbatman.com for web application vulnerabilities?

**Answer: 40.80.148.42**

Knew that any scan of the website would include the word "scan" in the alert/log, thought I might have to narrow it down further after but found only one source IP related, so we know it's 40.80.148.42. In the scans we see that the server responded with HTTP status 200 to 2 vuln scans: one to the root directory (just loading the home page and running basic scans/parsing), and one of the IIS 8.3 shortname scan in directory. The rest of the scans had 400/404 codes meaning the server rejected the request, but the 200 code means the server successfully responded with info to those two requests.

![Q1 Scan Detection](screenshots/q1-scan-detection.png)
![Q1 IIS 8.3 Scan](screenshots/q1-iis-scan.png)

---

### Q2: What company created the web vulnerability scanner used by Po1s0n1vy? Type the company name.

**Answer: Acunetix**

We can see in Q1 that the vuln scanner was made by Acunetix: "ET SCAN Acunetix Accept HTTP Header detected scan in progress"

---

### Q3: What content management system is imreallynotbatman.com likely using?

**Answer: Joomla**

Knew that any POST data to the site would include the CMS, so I simply queried for POST requests to the site and we can clearly see that the CMS is Joomla.

![Q3 CMS Joomla](screenshots/q3-cms-joomla.png)
![Q3 Joomla Admin](screenshots/q3-joomla-admin.png)

---

### Q4: What is the name of the file that defaced the imreallynotbatman.com website? Please submit only the name of the file with extension? (For example, "notepad.exe" or "favicon.ico")

**Answer: poisonivy-is-coming-for-you-batman.jpeg**

First I thought it would be related to a HTTP POST (assumed it was a web injection) and also assumed it would have poisonivy somewhere in it since attackers love notoriety, so I queried for poisonivy POST, but got no results. I realized they could have actually defaced the website via Joomla access, so I removed the POST filter and found the file: poisonivy-is-coming-for-you-batman.jpeg, along with confirmation that it was indeed server-side and not an HTTP injection. When removing the sourcetype filter to see Fortigate logs as well, we see the Batman web server reaching out to the jumpingcrab server at 23.22.63.114 for the defacement file.


![Q4 Defacement File](screenshots/q4-defacement-file.png)
![Q4 Fortigate Log](screenshots/q4-fortigate-log.png)

---

### Q5: This attack used dynamic DNS to resolve to the malicious IP. What fully qualified domain name (FQDN) is associated with this attack?

**Answer: prankglassinebracket.jumpingcrab.com**

We can see in Q4 the domain but just to confirm, I added DNS to the query.


![Q5 FQDN](screenshots/q5-fqdn.png)

---

### Q6: What IPv4 address has Po1s0n1vy tied to domains that are pre-staged to attack Wayne Enterprises?

**Answer: 23.22.63.114**

This is asking which server had the defacement attack ready to send to the Batman web server, which we already know from Q4 is 23.22.63.114 — the IP that prankglassinebracket.jumpingcrab.com resolves to.

---

### Q7: What IPv4 address is likely attempting a brute force password attack against imreallynotbatman.com?

**Answer: 23.22.63.114**

Knew that any login attempt will send a POST and that the form_data will include "passwd" (and that a brute force will have a high volume of them), so used this query to find count of src_IPs sending POSTs to imreallynotbatman where it was obviously 23.22.63.114 — all to the Joomla admin. Also when looking at the one login attempt from 40.80.148.42 on the Joomla admin, we can see that it was successful and lasting as its connection_type is "keep_alive" where all of the brute force attempts are "closed." I filtered the query (adding correct password "batman" to passwd form data) to track down where the brute force finally tried the correct combo to see how it differed from the other brute force attempts, and there was no difference. All of the attempts (including the successful one from 40.80.148.42) had the HTTP code of 303, meaning they were redirected to another site where they were either authorized or denied.


![Q7 Brute Force IP](screenshots/q7-brute-force-ip.png)
![Q7 Successful Login](screenshots/q7-successful-login.png)

---

### Q8: What is the name of the executable uploaded by Po1s0n1vy?

**Answer: 3791.exe**

First I assumed this would have been uploaded the same way the image defaced imreallynotbatman.com — server side from being sent from the attacker web server to the Batman server, so I queried for .exe files from the Batman server to the attacker server, but didn't find anything suspicious. I then deduced it must have been HTTP rather than server-side, so I queried for POST requests with .exe from the attacker IP to the Batman server (using the reasoning I was initially trying to use in Q4 — that to change the site it would require a POST from the attacker machine to the Batman web server). In this we can confirm with the upload of the .exe with the Joomla ExtPlorer file manager reference in the HTTP referer and URL fields that the attacker did indeed gain access to the admin controls of Joomla. The .exe was likely uploaded to gain persistence/a backdoor and to automate tasks for the attack, including the GET request to the attacker server for the defacement file.

![Q8 Executable Upload](screenshots/q8-executable-upload.png)
![Q8 ExtPlorer Confirm](screenshots/q8-extplorer-confirm.png)

---

### Q9: What is the MD5 hash of the executable uploaded?

**Answer: AAE3F5A29935E6ABCC2C2754D12A9AF0**

To find this, I knew I would need to search for the MD5 where 3791.exe was the process, so I queried for 3791.exe in the Sysmon logs, but found that obviously included processes like image loads and process terminations which all have their own unique MD5s. I knew I needed the original process creation (EventCode=1) where the child is 3791.exe and the parent is cmd.exe, and found the MD5 of AAE3F5A29935E6ABCC2C2754D12A9AF0.


![Q9 MD5 Hash](screenshots/q9-md5-hash.png)

---

### Q10: GCPD reported that common TTPs (Tactics, Techniques, Procedures) for the Po1s0n1vy APT group, if initial compromise fails, is to send a spear phishing email with custom malware attached to their intended target. This malware is usually connected to Po1s0n1vys initial attack infrastructure. Using research techniques, provide the SHA256 hash of this malware.

**Answer: (your SHA256 here)**

Had to go outside of Splunk to get this one since this malware was on the attacker's server and was never transmitted over the network. Went to ThreatMiner and searched for the attacking server IP 23.22.63.114, found an MD5 associated with it, which when clicking the hyperlink led to the SHA256 hash of the associated malware sample.

![Q10 ThreatMiner](screenshots/q10-threatminer.png)

---

### Q11: What special hex code is associated with the customized malware discussed in question 111?

**Answer: (your hex code here)**

Entered the SHA256 from Q10 into VirusTotal. One of the comments contained the hex code associated with the customized malware.

![Q11 VirusTotal](screenshots/q11-virustotal.png)

---

### Q12: What was the first brute force password used?

**Answer: 12345678**

Used the same query from Q7 to find all brute force attempts, then sorted by time to find the earliest event, then found 12345678 in the form_data field.

![Q12 First Password](screenshots/q12-first-password.png)

---

### Q13: One of the passwords in the brute force attack is James Brodsky's favorite Coldplay song. We are looking for a six character word on this one. Which is it?

**Answer: yellow**

Being somewhat of a Coldplay fan myself, I could think of a few popular songs that are 6 letters: "clocks", "sparks", "yellow", and "fix you" (7 with the space). Using a query to find all 6 letter passwords in the brute force, yellow appeared confirming it as the answer.

![Q13 Yellow Password](screenshots/q13-yellow-password.png)

---

### Q14: What was the correct password for admin access to the content management system running "imreallynotbatman.com"?

**Answer: batman**

We know from Q7 that this is "batman" — 40.80.148.42 made only one login attempt which was successful, and filtering the brute force results to that IP reveals the password used.


![Q14 Correct Password](screenshots/q14-correct-password.png)

---

### Q15: What was the average password length used in the password brute forcing attempt?

**Answer: 6.175**

First was trying the query with raw log data for the field type in the rex and was getting weird lengths (20-40 characters) and in turn a skewed average length. After printing the passwords in a table I saw extra characters being captured from non form_data fields where the password didn't cease after & or whitespace. Once I specified form_data I got the correct average of approximately 6.175 characters per password.

![Q15 Average Length](screenshots/q15-average-length.png)
![Q15 Rex Fix](screenshots/q15-rex-fix.png)

---

### Q16: How many seconds elapsed between the time the brute force password scan identified the correct password and the compromised login?

**Answer: 92.17 seconds**

Went simple here and just found the moment of compromised login with the only attempt from 40.80.148.42 (9:48:05.858 PM), then took the time that the web server found the batman password via brute force (9:46:33.689 PM), and simply subtracted to get 92.17 seconds.

![Q16 Compromised Login Time](screenshots/q16-compromised-login.png)
![Q16 Brute Force Time](screenshots/q16-brute-force-time.png)

---

### Q17: How many unique passwords were attempted in the brute force attempt?

**Answer: (your count here)**

Took all of the brute force attempts excluding the successful one from 40.80.148.42 because we know that 23.22.63.114 already found "batman" so it was a duplicate. Queried all brute force attempts then took a distinct count of the passwords.

![Q17 Unique Passwords](screenshots/q17-unique-passwords.png)

---

## Key Indicators of Compromise (IOCs)

| Indicator | Value |
|-----------|-------|
| Attacker scanning IP | 40.80.148.42 |
| Attacker brute force IP | 23.22.63.114 |
| Attacker hosting IP | 23.22.63.114 |
| Malicious domain | prankglassinebracket.jumpingcrab.com |
| Defacement file | poisonivy-is-coming-for-you-batman.jpeg |
| Uploaded executable | 3791.exe |
| MD5 of executable | AAE3F5A29935E6ABCC2C2754D12A9AF0 |
| Compromised CMS | Joomla |
| Compromised admin password | batman |

## Detection Summary
The investigation revealed a multi-stage attack against imreallynotbatman.com:
- Po1s0n1vy used Acunetix to scan for vulnerabilities and identify the Joomla CMS
- A brute force attack against the Joomla admin panel from 23.22.63.114 successfully identified the weak password "batman"
- The attacker logged in from 40.80.148.42 and uploaded a malicious executable (3791.exe) via the ExtPlorer file manager
- The compromised web server was made to fetch a defacement image from the attacker's hosting infrastructure
- Suricata and Fortigate both detected malicious activity but allowed it due to misconfigured policies
