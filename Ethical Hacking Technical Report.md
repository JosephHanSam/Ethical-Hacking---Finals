# Ethical Hacking Technical Report

**Client:** EL Corporation  
**Date:** May 08, 2024  
**Prepared by:** Marealie C. Espedillon and Joseph E. Lanzuela  

## Executive Summary

This technical report outlines the findings of the ethical hacking assessment conducted for EL Corp. The assessment aimed to identify vulnerabilities within EL Corp's systems and provide recommendations for remediation.

### Vulnerabilities Identified:

1. **SQL Injection Vulnerability**
   - **Description:** The application is vulnerable to SQL injection as attackers may use this vulnerability to perform malicious SQL queries, execute, and exploit it at runtime.
   - **Recommendation:** Apply parameters in queries or prepared statements to safeguard against SQL injection attacks and enhance security.

2. **Cross-Site Scripting (XSS) Issue**
   - **Description:** The app failed to check user inputs to block malicious script injections, which gave attackers the ability to intercept other users’ web pages' contents.
   - **Recommendation:** Initiate input validation and output encoding monitoring for XSS attack prevention. Utilize tools such as Content Security Policy (CSP) to minimize the risk that XSS attacks lead to.

3. **Weak Direct Object References**
   - **Description:** This application exposes internal access, allowing attackers to modify object references and access any data.
   - **Recommendation:** Impose adequate access management and execute authorization verifications over all user actions to ensure protection from unauthorized access to crucial data.

4. **Sensitive Data Exposure**
   - **Description:** The data transmitted is unencrypted due to reliance on outdated security protocols.
   - **Recommendation:** Implement encryption of data in transit (e.g., HTTPS) and at rest, ensuring all sensitive data are strongly encrypted using complex encryption algorithms.

5. **Broken Authentication**
   - **Description:** The app is designed with a poor security model, making it vulnerable to attacks such as brute force, session hijacking, and debulked keying.
   - **Recommendation:** Implement multi-factor authentication (MFA), strong password hashing algorithms, enforce account lockout policies (ELP), and implement secure session management (SSM).

6. **Security Misconfiguration**
   - **Description:** By default, the application and server configurations not covered by safety containers expose different accounts as well as sensitive information.
   - **Recommendation:** Monitor and upgrade server configurations consistently, deactivate vanity services, and perform basic server and application hardening practices regularly.

7. **XML External Entity (XXE) Exploitation**
   - **Description:** The program takes XML input from untrusted sources into consideration, creating vulnerabilities such as XXE attacks, allowing attackers to access local files, perform server-side request forgery (SSRF), and execute arbitrary code.
   - **Recommendation:** Consider disabling or safely processing XML input (XXE) through proper input validation and output encoding or deploying safe XML processing libraries.

8. **Cross-Site Request Forgery (CSRF)**
   - **Description:** The program is not capable of validating and verifying the source of requests, enabling CSRF attacks to commit unauthorized actions on behalf of authenticated users.
   - **Recommendation:** Introduce anti-CSRF tokens, measure the Referer header, and give cookies the SameSite attribute to prevent CSRF attacks.

9. **Remote Code Execution (RCE)**
   - **Description:** The app allows server-side command execution with user-defined input, enabling attackers to run any code they like.
   - **Recommendation:** Implement proper input validation, output encoding, and choose safe APIs to prevent code injections.

10. **File Upload Vulnerability**
    - **Description:** The application allows users to upload files without validation, making it prone to attacks such as inserting malicious files and overriding existing files.
    - **Recommendation:** Implement file type verification, limit file upload size, store uploaded files outside the web root, and ensure proper access rights for uploaded files.

### Recommendations for Remediation:

- Carry out periodic security assessments and penetration testing of the application to determine and mitigate weaknesses.
- Follow secure coding standards and security guidelines throughout the software development lifecycle.
- Ensure up-to-date software dependencies by frequently installing security patches.
- Train programmers and system administrators in common security flaws and vectors of attack.
- Develop a strong incident response plan to handle security incidents correctly.
- Install a web application firewall (WAF) to supplement existing protection against most web application attacks.
- Alert and track all security incidents to ensure prompt responses to any detected and actual security incidents.

In summary, the ethical hacking evaluation of EL Corporation's network has identified several dangerous vulnerabilities. By implementing the suggested mitigation principles and a proactive approach to cybersecurity solution implementation, EL Corporation can significantly enhance its asset protection and diminish the possibility of cyber threats.
