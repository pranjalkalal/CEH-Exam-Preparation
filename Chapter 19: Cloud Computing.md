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

# Container Basics
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

4. **Orchestrators**:
   - Transforms images into containers and deploys them.
   - Manages large-scale container deployments programmatically.

5. **Hosts**:
   - Operate and manage containers based on orchestrator instructions.

## Key Terms and Concepts
- **Docker**:
  - A leading platform for building, deploying, and managing containerized applications.
  - Features:
    - Docker Images: Base templates for creating containers.
    - Docker Daemon: Manages Docker objects and handles API requests.
    - Docker Registry (e.g., Docker Hub): Repository for official and custom container images.
    - Docker Files: Text files with commands for creating container images.

- **Orchestration**:
  - Automates the container lifecycle, including:
    - Provisioning and deployment.
    - Resource allocation and scaling.
    - Security and monitoring.
  - Popular tools: Kubernetes, OpenShift, Docker Swarm, Ansible.

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

# Hacking Cloud Services

## Cloud Vulnerability Scanning
- **Purpose**: Identifies security weaknesses in cloud-specific configurations, not just OS or application vulnerabilities.
- **Focus Areas**:
  - Cloud misconfigurations (e.g., AWS, Azure).
  - Vulnerable containers and container images.
  - Sensitive information leaks and insecure practices.

## Tools for Cloud Security Scanning
1. **Trivy**
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
 
    
## AWS Privilege Escalation Techniques
- **Metadata Service Exploitation**:
  - Access through SSRF vulnerabilities using the special IP `169.254.169.254`.
  - Gaining credentials (access key, secret key, session token) from `security-credentials`.

- **IAM Role Misconfigurations**:
  - Exploiting overly permissive IAM roles to escalate privileges.
  - Identifying unused or improperly configured roles using AWS CLI.

- **Key Discovery**:
  - Searching GitHub or forums for leaked keys and credentials.
  - Leveraging AWS CLI for detailed role and key analysis.

- **Public AMIs**:
  - Downloading and analyzing shared AMIs for sensitive information.

## Pentesting AWS Environments
- **Tools**:
  - **Pakku**: Framework for AWS penetration testing, automating enumeration and misconfiguration analysis.
  - **Cloud Goat**: Creates an insecure AWS environment for testing.
- **Focus Areas**:
  - IAM role analysis and misconfiguration.
  - Privilege escalation through found keys or roles.
  - Metadata service abuse.

## Key Security Concerns
1. **Publicly Accessible Resources**:
   - Public buckets and AMIs exposing sensitive data.
2. **IAM Misconfigurations**:
   - Roles with excessive permissions or improper restrictions.
3. **Metadata Service Exploits**:
   - Using SSRF vulnerabilities to gain access to AWS credentials.

**Key Takeaways**:
- Regularly scan cloud environments for vulnerabilities, especially configuration issues.
- Secure S3 buckets and IAM roles to avoid unauthorized access.
- Utilize ethical hacking tools like Pakku and Cloud Goat to simulate real-world scenarios and identify weaknesses.

# Cloud Security Controls

## What Are Cloud Security Controls?
- Measures implemented to enhance the security of cloud systems.
- Categories:
  - **Standard Security Controls**: Traditional measures applicable to cloud environments.
  - **Cloud-Specific Security Controls**: Tailored measures for cloud systems.


## Standard Security Controls
1. **Secure Software Development Lifecycle (SDLC)**:
   - Prevent flaws in cloud-hosted applications and APIs.
   - Example: Avoid leaking AWS credentials.

2. **Patching and Updates**:
   - Ensure operating systems, applications, and infrastructure are up-to-date.
   - Prevent exploitation of known vulnerabilities (e.g., EternalBlue).

3. **Change Default Configurations**:
   - Avoid using default credentials or settings.

4. **Firewalls and Intrusion Detection/Prevention**:
   - Use tools like IDS, IPS, and WAF for monitoring and defense.

5. **Logging and Monitoring**:
   - Track activity to detect anomalies and respond quickly.

6. **Denial-of-Service Mitigation**:
   - Use devices or services to prevent DoS/DDoS attacks.

7. **Encryption**:
   - Encrypt sensitive data at rest and in transit.

8. **Endpoint Protection**:
   - Deploy antivirus and EDR solutions.


## Cloud-Specific Security Controls
1. **S3 Bucket Permissions**:
   - Ensure correct access controls for S3 buckets.
   - Enable features like default encryption and versioning.

2. **Docker Security Best Practices** (via OWASP):
   - Use trusted Docker images.
   - Limit container capabilities and use "no new privileges" flags.
   - Disable inter-container communication when unnecessary.
   - Run Docker in rootless mode.

3. **Kubernetes Security Best Practices**:
   - Keep Kubernetes up-to-date.
   - Restrict API access using namespaces and network policies.
   - Conduct regular security audits.


## Tools for Cloud Security
1. **Qualys**:
   - Cloud vulnerability scanning and security assessments.

2. **Prisma Cloud**:
   - Cloud-native application protection platform by Palo Alto Networks.

3. **Aqua Security**:
   - Protects workloads, cloud platforms, and Kubernetes deployments.

4. **Tenable**:
   - Comprehensive tools for cloud and on-prem vulnerability management.

5. **Kubebench**:
   - Open-source tool for checking Kubernetes deployment security against CIS benchmarks.

6. **Sumo Logic**:
   - Provides observability and security analytics for cloud deployments.


**Key Takeaways**:
- **Consistency**: Regularly apply standard controls like patching and encryption.
- **Customization**: Leverage cloud-specific features like S3 policies and Kubernetes namespaces.
- **Tools**: Use security tools to automate assessments and maintain a robust posture.
- **Ongoing Process**: Security is a continuous journey requiring constant updates and vigilance.
