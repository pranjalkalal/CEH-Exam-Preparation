# Cloud Threats
## Cloud Computing Computing Threats
1. **Data breach/loss:** Data loss or leakage is highly dependent on cloud architecture and operation.
2. **Abuse and Nefarious Use of Cloud Services:** attackers create anonymous access to cloud services and perpetrate attacks such as password and key cracking, builduing rainbow tables,captcha-solving farms,launching dynamic attack points, botnet,ddos etc..
3. **Insecure in interfaces and APIs**
4. **Insufficient due dilligence:** Ignorance of CSP's cloud environment poses risks to operational responsibilities such as security encryption,incident response and other issues such as contractual issues, design and architectural issues.
5. **Shared technology issues**: Most underlying components that make up the cloud infrastructure (GPU,CPU caches) do not offere strong isolation in multi tenant environment so attacker can exploit other's application if they can exploit one tenant application vulnerability.
6. **Unknown risk profile**: organization are less involved with hardware and software ownership and maintanance in the cloud.
7. **Unsynchronized system clocks**: unsynchronized clocks can affect the working of automated tasks.
8. **Inadequate infrastructure design and planning**: shortage of computing resources and poor network design can result in unacceptable network latency or inability to meet agreed service levels.
9. **Confilcts between client hardening procedures and cloud environment**
10. **Loss of operational and security logs**
11. **Malicious insiders**
12. **Illegal access to cloud systems: Weak authentication and authorization controls**
13. **Loss of business reputation due to co-tenant activities**: resources are shared in cloud,thus malicious activity by one co-tenant might affect the reputation of the another, resulting in poor service delivery,data loss.
14. **Privilege escalation**: mistake in the access allocation.
15. **Natural disasters**
16. **Hardware failure**
17. **Supply chain failure**: security of the cloud is directly proportional to security of each link and extent of dependency on third parties.
18. **Modifying network traffic**: network traffic may be modified due to flaws while provisioning or de-provisioning the network or vulnerabilities in communication encryption.
19. **isolation failure**: attacker may try to control operations of other cloud customers to gain illegal access to the data.
20. **Cloud provider acquisition**: acquisition of cloud provider may increase the probability of tactical shift which may put non-binding agreement s at risk.
21. **Management interface compromise**: When access to resource combined with remote access and web browser vulnerabilities then it enhances risk.
22. **Network Management failure**: poor network management leads to network congestion, misconnection,misconfiguration.
23. **Authentication attacks**
24. **VM-level Attacks**: this threat arises due to the existance of vulnerability in the hypervisors.
25. **Lock in**: difficulties experianced by user when migrating from in-house systems oe from one cloud service provider to another due to lack of tools,procedures or standard data formats poses potential threats to data, application and service portability.
26. **Licensing risks**: organization may incur a huge licensing fee if the software deployed in the cloud is charged on per instance basis.
27. **Loss of governance**: customer gives up control to the csp including control of issues that may affect security.
28. **Loss of encryption keys**
29. **Risks from changes of jurisdiction**: posibility of risk that data or information system may be blocked or impounded by gov or other org.
30. **Undertaking malicious probes or scans**: malicious probes or scanning allows attackers to collect sensitive information that may lead CIA loss.
31. **Theft of computer equipment**
32. **cloud service termination or failure**
33. **subpoena and e-discovery**: if customer data or service are subpoenaed or subjected to cease and desist request from authorities or third parties,access to such data and services may be compromised.
34. **Improper data handling and disposal**: disfficult to ascertain data handling due to limited access to cloud infrastructure.
35. **Loss or modification of backup data**: Attacker might exploit vulnerability such as SQL injection,insecure user behavior like storing password,reusing password to gain access to the data backup in cloud.
36. **Compliance risks**
37. **Economic Denial of sustainability (EDOS)**: if attacker engages the cloud with malicious service that consumes a lot computational power abd storage from the cloud server,then legimate account holder is charged for this.
38. **Lack of security Architectures**
39. **Hijacking Accounts**

## Container Vulnerabilities
  1. **Impetuous Image Creation** : Careless Creation of images by not considering the security safeguards or control aspects leads to vulnerabilities in the images.
  2. **Unreliable Third-Party Resources**: Using untrusted resources causes server threat and make the resources vulnerable to malicious attacks.
  3. Unauthorized Access
  4. Insecure Contrainer Runtime Configurations
  5. Data Exposure in Docker Files
  6. Embeded Malware
  7. Non-Updated Images
  8. Hijacked Repository and Infected Resources
  9. Hijacked Image Registry
  10. Exposed Service due to open Ports
  11. Exploited applications
  12. Mixing of workload sensitivity levels
## Kubernetes Vulnerabilities
  1. No Certificate Revocation
  2. Unauthenticated HTTPS Connections
  3. Exposed Bearer Tokens in logs
  4. Exposure of sensitive data via environment variables
  5. Secrets at rest not encrypted by default
  6. Non-Constant Time password comparison
  7. Hardcoded credential paths
  8. log rotation is not atomic
  9. No back off process for Scheduling
  10. No Non repudiation
## Cloud Attacks
  1. service Hijacking using Social Engineering
  2. service Hijacking using Network Sniffing
  3. Side-Channel Attacks or Cross-guest VM
  4. **Wrapping Attack**: It is performed during translation of the SOAP message in TLS layer where attacker duplicate the body of the message and send it to the server as legitimate user.
  5. **Man-in-the-Cloud (MITC) Attack**: advanced version of MITM. here MITC attacks are performed by abusing cloud file synchronization services such as g.drive,dropbox for data compromise,C&C,data exfiltration and remote access.
  6. **Cloud Hopper Attack**: this attacks are triggered at the managed service providers and their users.
  7. **Cloud Cryptojacking**: Cryptojacking is the unauthorized use of the victim's computer to stealthily mine digital currency.it is highly lucrative
  8. **Cloudborne Attack**: it is vulnerability residing in a bare-metal cloud server that enables attackers to implement malicious bacdoor in its firmware
  9. **Instance Metadata service attack (IMDS)**: It provides information about instance,its associated network and software configured to run the instance.attackers performed this attack as zero day vulnerability using reverse proxy.
  10. **Cache poisoned Denial of Service (CPDOS)/Content Delivery Network(CDN) Cache poisoning attack**: It create malformed or oversized HTTP requests
  11. **Cloud snooper attack**: It triggerd at aws security groups to compromise the target server and extract sensitive data stealthy.
  12. **Golden SAML attack**: This attack performed to target identity providers on cloud networks such as AD fedration Service which utilize SAML protocol for authentication and authorization of users.
  13. other cloud attacks
      1. Session Hijacking using XSS attack
      2.  Session Hijacking using session riding
      3.  DNS attack
         - types:
           1. DNS poisoning
           2. Cybersquatting
           3. Domain Hijacking
           4. Domain Snipping
            
      4.  SQL injection attack
      5.  Cryptanalysis attacks
      6.  DoS and DDoS attacks
      7.  Man in the Browser Attack
      8.  Metadata spoofing attack
      9.  Cloud Malware injection attack
## Cloud Malware
1. **Hildegard**: It is designed to exploit misconfigured kubelets in kubernetes cluster and infect all containers present in kubernetes environment. Use this malware to perform resource hijacking,Crypto jacking,DoS,application eruption, Crypto mining etc..                        Fetures: bypass static analysis tool using IRC agent(Ziggystartux),DNS monitoring tool by altering system DNS resolvers,utilize 2 c2 communication channels- tmate and IRC both work almost similar
2. Denonia
3. LwmonDuck
4. RansomCloud
5. DBatLoader/ModiLoader
6. Goldbackdoor
   
# terms
- CASBs: Cloud access security brokers
- UDDI: Universal Description Discovery and Integrity
- SOAP: Simple Object Access Protocol
- WSDL: Web Service description Language
- MSPs: Managed Service providers
- BMC: baseboard management control
- IPMI: intelligent plateform management interface
