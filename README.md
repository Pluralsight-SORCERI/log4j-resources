# log4j-resources
Collection of resources for responding to the Log4j set of vulnerabilities.

[Pluralsight - Log4j Vulnerability: What you should know](https://app.pluralsight.com/library/courses/log4j-vulnerability-what-you-should-know/)

**The current recommendation for remediation teams is to immediately path to the newest version of log4j.**

## Vulnerabilities
The remote code execution (RCE) vulnerabilities are being referred to as "Log4Shell". There have been a few CVEs related to this overall vulnerability:
- [CVE-2021-44228](https://cve.mitre.org/cgi-bin/cvename.cgi?name=2021-44228)
- [CVE-2021-45046](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-45046)
- [CVE-2021-44832](https://cve.mitre.org/cgi-bin/cvename.cgi?name=2021-44832)

Additional Recent Log4j v2.x Vulnerabilities:
- [CVE-2021-54105](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-45105)

Recent Log4j v1.x vulnerabilitites:
- [CVE-2021-4104](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4104)
- [CVE-2021-42550](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-42550)

SolarWinds LDAP authentication:
- [CVE-2021-35247](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-35247)

## Other Important Notes:
- Apache has released new versions that address the concerns found from additional vulnerabilities
- The vulnerability was initially discoveredc and privately reported by Chen Zhaojin of Alibaba on November 24, 2021
- The exploit was first detected by Cloudflare on December 1, 2021
- A proof of concept of the exploit was published on GitHub on December 9, 2021

## Helpful Tools, Scanners, and Repositories
Official CISA Guidance & Resources
- https://github.com/cisagov/log4j-affected-db

Security Advisories / Bulletins / Vendor Responses linked to Log4Shell:
- https://gist.github.com/SwitHak/b66db3a06c2955a9cb71a8718970c592

List of Vulnerable Packages: 
- https://github.com/NCSC-NL/log4shell/tree/main/software

Log4Shell detector: 
- https://github.com/Neo23x0/log4shell-detector

Detector Gist - Log4j RCE CVE-2021-44228 Exploitation Detection:
- https://gist.github.com/Neo23x0/e4c8b03ff8cdf1fa63b7d15db6e3860b

## Webcasts
BHIS - Talkin' Bout [infosec] News 2021-12-13 | Log4j | The Floor is Java 
- https://www.youtube.com/watch?v=igoDXnkYDy8

SANS - What do you need to know about the log4j (Log4Shell) vulnerability? 
- https://www.sans.org/blog/what-do-you-need-to-know-about-the-log4j-log4shell-vulnerability/

VMWare - What you need to know about Log4j
- https://core.vmware.com/blog/virtually-speaking-podcast-what-you-need-know-about-log4j 

## Additional Articles and References
Rapid7 log4j Analysis and Proof of Concept:
- https://attackerkb.com/topics/in9sPR2Bzt/cve-2021-44228-log4shell/rapid7-analysis

Apache Log4j Security Vulnerabilities 
- https://logging.apache.org/log4j/2.x/security.html

Log4j2 Vulnerability “Log4Shell” (CVE-2021-44228) 
- https://www.crowdstrike.com/blog/log4j2-vulnerability-analysis-and-mitigation-recommendations/

How Do I Find My Servers With the Log4j Vulnerability? 
- https://www.darkreading.com/dr-tech/how-do-i-find-which-servers-have-the-log4j-vulnerability-

Log4Shell: RCE 0-day exploit found in log4j 2 
- https://www.lunasec.io/docs/blog/log4j-zero-day/

Finding applications that use Log4J 
- https://www.rumble.run/blog/finding-log4j/

Explaining Log4Shell in Simple Terms 
- https://www.cygenta.co.uk/post/log4shell-in-simple-terms

Second security flaw found in Log4Shell software 
- https://www.tomsguide.com/news/new-log4j-flaw
