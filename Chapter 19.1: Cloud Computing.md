# Cloud Computing Overview

## Introduction
- Cloud computing is integral to modern technology.
- The cloud is essentially "someone else's computer."

## Types of Cloud Services
1. **IaaS (Infrastructure as a Service)**
   - Provides virtualized computing resources over the internet.
   - Users manage applications, data, runtime, middleware, and OS.
   - Providers manage virtualization, servers, storage, and networking.

2. **PaaS (Platform as a Service)**
   - Offers hardware and software tools over the internet.
   - Users manage applications and data.
   - Providers handle runtime, middleware, OS, virtualization, servers, storage, and networking.

3. **SaaS (Software as a Service)**
   - Delivers software applications over the internet.
   - Providers manage all aspects of the service.
   - Example: Google Suite (Gmail, Google Docs, etc.).

4. **IDaaS (Identity as a Service)**
   - Manages user identities and access.
   - Includes single sign-on (SSO) and multi-factor authentication (MFA).

5. **SECaaS (Security as a Service)**
   - Provides security services via the cloud.
   - Includes automated penetration testing, antivirus (AV), and endpoint detection and response (EDR).

6. **CaaS (Container as a Service)**
   - Offers container-based virtualization.
   - Example: Amazon S3 buckets and other container services.

7. **FaaS (Function as a Service)**
   - Enables functions to be executed in the cloud.
   - Example: AWS Lambda.

## Responsibility Areas
- **On-premises:** User is responsible for all aspects of infrastructure and software.
- **IaaS:** Provider handles physical aspects and virtualization; user handles software and data.
- **PaaS:** Provider manages everything except applications and data.
- **SaaS:** Provider manages all aspects of the service.

## Deployment Models
1. **Public Cloud**
   - Services offered over the public internet and available to anyone.
   
2. **Private Cloud**
   - Exclusive to a single organization, offering more control and security.

3. **Community Cloud**
   - Shared among multiple organizations with common concerns.
   - Example: Healthcare providers sharing infrastructure for secure data exchange.

4. **Hybrid Cloud**
   - Combination of public, private, and community cloud models.

5. **Multi-Cloud**
   - Utilizes services from multiple cloud providers for redundancy or specialized capabilities.
   - Managed through a single interface by third-party brokers.

## NIST Cloud Deployment Reference Architecture
1. **Cloud Consumer**:
   - End user or organization using the cloud service.

2. **Cloud Provider**:
   - Entity providing cloud services.

3. **Cloud Carrier**:
   - Enables network connectivity between consumers and providers.

4. **Cloud Broker**:
   - Manages and integrates multiple cloud services for consumers.

5. **Cloud Auditor**:
   - Conducts independent assessments of cloud implementations.

## Cloud Storage Architecture
1. **Front-End**:
   - User-facing interaction layer (e.g., APIs, web apps).

2. **Back-End**:
   - Physical hardware (servers, networking).

3. **Middleware**:
   - Handles data deduplication, replication, and storage efficiency.


## Categories of Cloud Brokers
1. **Service Intermediation**
   - **Description:** Enhances an existing service by improving specific capabilities.
   - **Example:** A broker might add security features to a basic cloud storage service, providing encryption and access control that the original service lacks.

2. **Service Aggregation**
   - **Description:** Combines multiple services into one unified service. It handles data integration and ensures the services work together seamlessly.
   - **Example:** A broker could integrate cloud storage from one provider, computing power from another, and database services from a third into a single package.

3. **Service Arbitrage**
   - **Description:** Provides flexibility in choosing services from multiple providers based on current conditions and requirements. The broker evaluates and selects the best options dynamically.
   - **Example:** A broker might switch between cloud providers for the best price or performance for a specific task, such as shifting from AWS to Azure if Azure offers a better rate or performance for a given workload.

**Key Takeaway**: Cloud computing provides various service and deployment models, each with unique responsibility areas, enabling flexibility and scalability for different needs.

**Fog Computing**: It is distributed and independent digital environment in which application and data storage are between data source and cloud service.
   - act as intermediatry between h/w and remote server and also called intelligent gateway.
     
**Edge Computing**: it is distributed decentralized computing model in which data processing is performed close to the edge.
   - helps in building automation systems 

# Container Technology
- **Definition:** A container is a portable software package that includes everything needed to run an application, such as configuration files, libraries, and dependencies. This ensures consistency, scalability, and cost-effectiveness.
- **Advantages:** Containers simplify the development process by providing predefined environments, reducing setup time, and ensuring applications run consistently across different platforms.

## Five-Tier Container Architecture (as defined by EC-Council)
1. **Developer Machines**:
   - Used for image creation, testing, and accreditation.
   - Ensures the image is ready for use.

2. **Testing and Accreditation Systems**:
   - Verifies and validates image contents.
   - Signs the images for integrity and readiness.

3. **Registries**:
   - Stores container images.
   - Supports image delivery via orchestration software.
   - popular registry services include Docker Hub,Amazon Elastic Container Registry (ECR), Docker Trusted Registry (DTR) etc..

4. **Orchestrators**:
   - orchestrators are tools that allow DevOps administrators to fetch images from the registries,deploy them into containers and manage container operation.
   - Transforms images into containers and deploys them.
   - Manages large-scale container deployments programmatically.
   - popular orchestrators: kubernetes,docur swarm,nomad,mesos etc..

5. **Hosts**:
   - Operate and manage containers based on orchestrator instructions.

**Three phases of container lifecycle:**
   1.Image creation,Testing and accreditation
   2.Storage and retrieval of image
   3.Deployment and Management of container
   
## Key Terms and Concepts
- **Docker**:
  - A leading platform for building, deploying, and managing containerized applications. it is PAAS through os level virtualization.
  - **Doken engine**: it is client/server application installed on host that allows to develop, deploy and run applications using this components: Server,Rest API,Client CLI
  - **Docker Swarm**: It is mode in D.engine which allows to manage multiple D.E withing D.platform
  - **Doker Architecture**:  
     - components: Doker Daemon, Docker Client, Docker Registries
  - **Doker Objects**
     - Images,Containers,Services,Networking,Volumes
  - **Doker Operations**
  - **Container network model CDN**
    - 2 drivers:IPAM Driver(IP adress mannagement),network driver
    - D.E have 5 native network drivers(Host,Bridge,overlay,MACVLAN,None)
       - Host: By using a host driver, a container implements the host networking stack.
       - Overlay: An overlay driver is used to enable container communication over the physical network infrastructure.
       - MACVLAN: A macvlan driver is used to create a network connection between container interfaces and the parent host interface or sub-interfaces using the Linux MACVLAN bridge mode.
       - None: A none driver implements its own networking stack and is isolated completely from the host networking stack. 
    - 3 remote drivers(contiv,weave,kuryr)
       
   - Docker Images: Base templates for creating containers.
   - Docker Daemon: Manages Docker objects and handles API requests.
   - Docker Registry (e.g., Docker Hub): Repository for official and custom container images.
   - Docker Files: Text files with commands for creating container images.

- **Orchestration**:
  - Automates the container lifecycle, including:
    - Provisioning and deployment.
    - Resource allocation and scaling.
    - Security and monitoring.
  - Popular tools: Kubernetes(K8), OpenShift, Docker Swarm, Ansible.

- **Cluster**: set of two or more connected nodes that run parallelly to complate task.
   - 3 types: Highly available(HA) or fail-over, Load Balancing, High performance computing

## Security Challenges in Containerization
1. **Untrusted Images**:
   - Public containers may contain outdated software or vulnerabilities.
   - Perform thorough checks before deployment.

2. **Container Breakout**:
   - Attackers may exploit vulnerabilities to escape the container and access the host system.
   - Running containers as root increases risks.

3. **Insecure Secrets**:
   - API keys, usernames, and passwords stored insecurely in containers can be exploited.

4. **Noisy Neighbor**:
   - A container consuming excessive host resources can cause other containers to fail.

5. **Vulnerable Source Code**:
   - Containers used for testing may expose organizations to attacks if insecure code is deployed.

## Key Takeaways
- Containers simplify development by bundling all necessary components into a portable format.
- Security diligence is crucial when using third-party containers or deploying at scale.
- Tools like Docker and Kubernetes streamline containerization and orchestration processes.
- Containers are not buckets—though both can "contain" items, they serve distinct purposes in technology.

# Serverless computing
 - It is emerging technology for deployment of cloud based enterprise application built on container and microservices.
 - it is function as service model
 - microsoft azure functions, aws lambda,google cloud function,IBM c.f, AWS Fargate,Alibaba cloud function compute.

# Cloud Computing Treats

## OWASP Top 10 Cloud Security Risks
   - R1- Accountability and Data Ownership: because of cloud data ownership is in the hand of CSP.
   - R2-User Identity Fedration: CSPs have less control over the user lifecycle
   - R3-Regulatory Compliance: following regulatory compliance can be complex because cloud is multiregion technology and it's may not secure the data which secure in contry which also secure in another country.
   - R4-Business Continuity and Resilliency: if cloud provider handles business continuity improperly then here risk possible.
   - R5-User privacy and Secondary Usage of Data: social websites data stores in cloud and  most social application providers mine user data for secondary usage.
   - R6-Service and Data integration: when data transfered from end user to cloud data center there need to implement proper security outherwise transit unsecure data are suspectible to evesdroping and interception attack.
   - R7-Multi Tenancy and Physical Security: Inadequate logical segregation may lead to tenants interfering with each other's security fetures.
   - R8-Incidence Analysis and forensic support: owning to distrubuted storage of logs across the cloud,law enforcingagencies may face problem in forensics recovery.
   - R9-Infrastructure Security: Configuration baselines of the infrastructure should comply with the industry best practices because there is constant risk of malicious actions.
   - R10-Non-Production Environment Exposure: Using non-production environments increases the risk of unauthorized access, information disclosure, and information modification.
     
## OWASP Top 10 serverless security Risks
- Serverless applications are vulnerable to the same type of attacks as traditional web applications.
  - A1-injection
  - A2-Broken Authentication
  - A3-sensitive data exposure
  - A4-XML external entity (XXE)
  - A5-Broken access control
  - A6-Security Misconfiguration
  - A7-XSS
  - A8-Insecure Deserialization
  - A9-Using Components with known vulnerabilities
  - A10-Insufficient logging and monitoring
## Cloud Computing threats
   - Insufficient Due Diligence: ignored CSP's cloud environment poses risks to operational responsibilities such as security, encryption..
   - Unsynchronized system clocks: Unsynchronized clocks can affect the working of automated tasks.
   - Economic denial of sustainability-EDOS: executes malicious code that consumes a lot of computational power and storage from the cloud server, then the legitimate account holder is charged for this kind of computation until the primary cause of CPU usage is detected  

# Cloud Hacking 
## Cloud Vulnerability Scanning
- **Purpose**: Identifies security weaknesses in cloud-specific configurations, not just OS or application vulnerabilities.
   - main objective of hacking the cloud environment is gaining access to user data and blocking access to cloud service 
- **Focus Areas**:
  - Cloud misconfigurations (e.g., AWS, Azure).
  - Vulnerable containers and container images.
  - Sensitive information leaks and insecure practices.

## Tools for Cloud Security Scanning
1. **Trivy**
   - Container image vulnerability scanning automated tool
   - Comprehensive security scanner for container images, Git repositories, virtual machine images, Kubernetes, and AWS.
   - Detects CVEs, IAC issues, sensitive information leaks, and software license violations.

2. **Clair**
   - Open-source tool for static analysis of vulnerabilities in application containers (OCI and Docker).

3. **DAGDA**
   - Performs static analysis for known vulnerabilities, malware, and anomalous activities in Docker images/containers.

4. **Twistlock**
   - Cloud-native cybersecurity platform for full lifecycle security in containerized environments and cloud-native applications.

5. **Sysdig**
   - Focuses on Kubernetes security, enumerating key storage, API objects, configuration files, and open ports.

## S3 Discovery and Enumeration
- **Common Issues**:
  - Publicly readable buckets exposing sensitive data (keys, credentials, private files).
  - Incorrect permissions allowing unauthorized access.
- **Key Tools**:
  - **Grey Hat Warfare**: Enumerates open S3 buckets and their contents.
  - **S3 Scanner**: Command-line tool for identifying open buckets.
  - **Bucket Kicker**: Identifies and inspects accessible buckets.
- **Manual Methods**:
  - Checking source code for S3 bucket URLs.
  - Using brute-forcing techniques with tools like Burp Suite or custom scripts.
    
**Bucket Permission Enumeration using S3Inspector**

**enumerationg Kubernetes etcd**: etcd is a distributed and consistent key-value storage, where kubernetes cluster data, service discovery details,API objects,etc.. are stored
- attackers examine etcd processes,configuration files,open ports(identifying port number 2379) etc.. to identify endpoint connected to kubernets environment.
- for identify location of etcd server and PKI information: ps -ef | grep apiserver
  
**enumerating Azure AD accounts**
- for perform azure ad enumeration use tool like Azurecar
- for perform password spraying use tool like Ruler
  
 **Gathering cloud keys through IMDS attack**   
 - use curl to perform this attack

**Nimbostratus**: used for fingerprinting and exploiting amazone cloud infrastructures.
 - can able to : Dump credentials,dump permissions,dump instance metadata,create DB snapshot,create new user
   
**Steps for exploit misconfigured AWS S3 Buckets**

   1. Identify S3 bucket
   2. Setup AWS CLI
   3. Extract access key
   4. Cnfigure AWS-Cli
   5. Identify vulnerable S3 buckets
   6. exploit s3 buckets
      
**Compromise AWS IAM credentials**

   - Repository Misconfiguration
   - Social engineering
   - Password Reuse
   - vul. in aws hosted application(SSRF,Reading local file)
   - Exploiting third party software
   - Insider threat
     
**Hijacking Misconfigured IAM Role using Pacu**: AWS exploitation framework for enumerating and hijacking IAM roles,and can find assuming role is possible or not

**Cracking AWS Access keys using Dumpster Driver**: it allows attacker to examine lasrge volume of file types while scanning hardcoded secret keys also this tool can identify any potential secret leaks and hardcoded passwords in target cloud service.

**Exploiting Docker Container on AWS using Cloud Container Attack tool CCAT**

   1. Abuse AWS Credentials
   2. Pull the target docker image
   3. create backdoor image
   4. push backdoor docker image

**Serverless-Based Attacks on AWS lambda**

   - **Black Box senario**: attackers make certain assumptions regarding specific feature as they do not have prior information about internal working environment.
   - **White box senario**: have prior information about environment
     
**Exploiting Shadow Admin in AWS**:Shadow admins are user accounts with specific permission that allow attackers to penetrate target cloud network.
   - some techniques to abuse shadow admin permission
      1. elevating access permission
      2. modifying existing roles
      3. creating new accounts
         
   - Shadow admin scan tools
      1. SkyArk: contains 2 main scanning modules-AWStealth and AzureStealth
      2. Red-shadow
      3. ACLight2
         
**Exploiting Docker Remote API**: Retrive files from Docker Host,scanning internal network,retriving credentials,querying databases

**Hacking Container Volumes**
   - kubernetes support different types of vulumes like Network file system-NFS, and internet small computer system interface-iSCSI
   - Accessing Master nodes: if attackers can gain access to API or etcd,they can retrive conf. detail of mounted volumes
   - Accessing Nodes: Kubelet manages the pods, so if attackers can access a node in pod , they can easily gain access to all the volumnes used within pod.'df' command used
   - Accessing Container: By gaining access to the container, attacker can configure a hostpath volume type to retrive sensitive info from node.

**CloudGoat 2 - vulnerable by design AWS Deployment tool**:
   - CloudGoat is Rhino security labs 'vulnerable by design' aws deployment tool

**Gaining access by exploiting SSRF vulnerability**

## AWS Privilege Escalation Techniques
   1. create a new policy version
   2. assign the default policy version to an existing version
   3. create an EC2 instance with existing instance profile
   4. Create new user access key
   5. create/update login profile
   6. attach policy to user/group/role
   7. create/update inline policy for user/group/role
   8. add user to group
**Escalating Privileges of Google Storage Buckets using GCPBucketBrute**
    - GCPBucketBrute is script based tool that allows to enumerate google storage bucket.

**Privilege escalation using misconfigured user account in azure AD**
   - attacker discovers normal user account in azure AD using tools such as Bloodhound or AzureHound

**creating backdoor accounts in aws**
   - attackes use tools like endgame aand pacu to create backedoor .

**Backdooring Docker Image using Dockerscan**
   - dockerscan is docker analysis and hacking tool

**Maintaining Access and covering tracks on AWS by manipulating cloud trail service**
   - for covering tracks: attacker disable logging functionality in aws by pausing cloudtrail service then maintain access to aws.

**AWS Hacking tool: AWSpwn**
   - reconnaissance
   - Privilege escalation
   - Maintaining Access
   - Clearing tracks
     
- cli_lambda -> A Lambda function that acts as an AWS cli proxy and does not require credentials.
  
- rabbit_lambda -> An example Lambda function that responds to user-delete events by creating more copies of the deleted user.

- backdoor_created_roles_lambda -> A Lambda function that adds a trust relationship to each newly created role.

- backdoor_created_users_lambda -> A Lambda function that adds an access key to each newly created user.

# Cloud Security

## Cloud Security Controls?
- Measures implemented to enhance the security of cloud systems.
  
- **Cloud Security Control Layers**:
   1. Application : SDLC,binary analysis,Web app firewall,Transactional sec
   2. Information: DLP(Data loss prevention),CMF,Database activity monitoring,encryption
   3. Management:GRC(Governance risk compliance),IAM,VA/VM,Patch management,conf.manag.,monitoring
   4. Network: NIDS/NIPS,firewall,DPI,anti-ddos,QoS(Quality of service),DNSSEC,OAuth
   5. Trusted Computing: H/W and S/W RoT and API's
   6. Computation and storage: Host based firewall,HIDS/HIPS,Integrity and File/log management,encryption,masking
   7. Physical: physical plant security,CCTV,Guards

## Cloud computing Security Considerations
   - services should be tailor made by vendor
   - CSPs should provide highr multi-tenancy-for optimum utilization
   - Should implement Disaster recovery plan
   - monitor Quality of service to maintain service level agreements
   - data integrity
   - should be fast,reliable and quick response
   - Symmetric and asymmetric algo implemented
   - load balancer should be incorporated
   - use zero trust principles to segment business applications
## Placement of Security Controls in cloud
**Categories of security controls**
   
   1. Deterrent Controls: reduce attacks on cloud system
      - Warning sign on the fence or property to inform potential attackers of adverse consequences if the proceed attack.
   2. Preventive Controls: Strengthen the system against incidents by minimizing or eliminating vulnerabilities
      - Strong authentication mechanism to prevent unauthorized use of cloud system
   3. Detective Controls: Detect and React appropriately to occurring incidents
      - Employing IDSs,IPS  
   4. Corrective Controls: Minimize the consequences of incident by limiting damage
       - Restoring system backups
      
## Best Practices for securing Cloud
   - Regularly undergo AICPA SAS 70 Type II audits
   - verify own cloud in public domain blacklists
   - 
## NIST Recommendation for Cloud security
   - Assess the risk posed to the client's data,s/w and infra.
   - select an appropriate deployement model
   - use auditing process for data protection and software isolation
   - Renew SLAs in case of Security gap between organization's scurity requirnment and cloud provider's standards
   - use incident detection and reporting mechanism
   - analyze security objectives
   - Enquire about responsibility of data privacy and security issues in cloud.
## Security Assertion Markup Language-SAML
   - SAML is popular Open standard protocol used for authentication and authorization between communicationg parties.
   - it can be offered as software as a service to be installed at service provider(SP)
   - **It consists 3 entities**
      1. Client or user : entity with valid account
      2. Service provider(SP) : It is server hosting application for users
      3. Indentity Provider(IdP) : entity within system that stores user directories and validating mechanism
## Cloud Network Security
   1. VPC
   2. public private subnets
   3. Transit Gateways : it is network routing solution
   4. VPC endpoiints : 2 types-Interface and gateway load balancer
## Cloud Security Controls
  - **Cloud Application Security**: known as safety net in zero trust security implementation
  - **High Availability Across Zones**
  - **Cloud Integration and Auditing**
      - cloud integration is the process of grouping multiple cloud environments togather in the form of public or hybrid cloud
      - Cloud auditing is process of analyzing services.
  - **Security Groups**
  - **Instance Awareness** : the cloud based kill chain model describes the possibilities of using fake instances cor C2C to exfiltrate data from cloud
## Kubernetes V.and solutions
  1. No certificate Revocation
  2. Unauthenticated HTTPS Connections
  3. Exposed Bearer Tokens in logs
  4. exposure of sensitive data via env.var.
  5. Secrets at rest not encrypted by default
  6. Non-constant time password comparison
  7. Hardcoded credential paths
  8. log rotation is not atomic
  9. No Back-off process for scheduling
  10. no non-repudiation
      
## Serverless security Risks and solutions
   1. A1-Injection
   2. A2-Broken authentication
   3. A3-sensitive data exposure
   4. A4-XXE
   5. A5 Broken access control
   6. A6-security misconfiguration
   7. A7-XSS
   8. A8-insecure deserialization
   9. A9-using components with known vulnerabilities
   10. A10-Insufficient logging and monitoring
   
## Best Practices for Container Security

## B.P for Docker Security
   - use linux security modules such as seccomp,apparmor and SELinux to gain fine-grained control over the processes
   - use --read-only flag
   - use InSec and DevSec to detect docker vulnerability
     
## B.P for Kubernetes Security
   - use copy then rename method
   - use online certificate status protocol-OCSP stapling to check the revocation status of certificate
## B.P for Serverless Security
## Zero Trust Networks
## Org/Provider cloud security compliance checklist
## International Cloud security Organizations
   - Cloud security alliance-CSA is nonprofit global organization
## Cloud Security Tools
  ### Cloud Security Tools
   **Shadow Cloud Asset Discovery Tools**
   - **Cisco Umbrella** 
   - **Securiti**
   - **Microsoft Defender for cloud apps**
   - **fire compass**
   - **data theorem**
   - **cloudcodes**
  **Qualys Cloud Platform**
  **Fidelis cloudpassage Halo**
  **Lookout CipherCloud**
      - saveral developing secure access service edge-SASE categories,including CASB, Zero trust network access-ZTNA, Secure web gateway-swg and data loss prevention-DLP
   -   Data-aware cloud security
   -   Netskope security cloud
   -   prisma cloud
   -   ForgeRock Identity Cloud
   -   Deep Security
  ### Container security tools
   - Aqua,sysdig flaco,anchore,neuvector,lacework,tenable.io container sceurity
  ### Kuberenetes security tools
   - Kube-bench,Alcide advisor,advanced cluster security for kub,aqua kub.sec.,kubexray,sumo logic
  ### Serverless Application Security Solutions
   - CloudGuard,Synk,Aqua Security for FAAS,Prisma cloud,Dashbird,Thundra

  ### Cloud Access security Broker-CASB
   - CASBs are on-premise or cloud-hosted solutions responsible for enforcing security,compliance and governance policies for cloud app.
   -  these are placed between CSP and consumer
   -  Azure security services includes CASB functionality
   -  **Fetures of CASB**
       1. Visibility into cloud usage
       2. Data security
       3. Threat protection
       4. Compliance
   - CASBs offers: Firewalls,authentication,WAFs,DLP
   - CASB solutions: Forcepoint CASB,Cloudcodes,cisco cloudlock,bitglass cloud security,microsoft cloud app security,fortiCASB
 ### Netx Generation Secure Web Gateway-NG SWG
  - It is Cloud based security solution
  - NG SWG solutions: Netskope NG SWG,Cloudflare Gateway,Quantum Next genration firewall security gateway

# Summary
- **Pacu**, an open source AWS exploitation framework for enumerating and hijacking IAM roles
- **DumpsterDiver**: DumpsterDiver allows attackers to examine a large volume of file types while scanning hardcoded secret keys such as AWS access keys, SSL keys, and Microsoft’s Azure keys
- **Alcide Advisor**: As Kubernetes is a de facto container deployment and management tool, its workloads need to be regularly monitored and secured with appropriate security implementations. Security professionals use tools, such as Kube-bench, Alcide Advisor, and StackRox, to secure the Kubernetes environment.
- **CloudGoat AWS**: CloudGoat is Rhino Security Labs' "Vulnerable by Design" AWS deployment tool. It allows you to hone your cloud cybersecurity skills by creating and completing several "capture-the-flag" style scenarios
