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
- **Cloud Consumer:** Principal stakeholder using the service.
- **Cloud Provider:** Entity offering cloud services.
- **Cloud Auditor:** Performs independent assessments of cloud services.
- **Cloud Carrier:** Provides network connectivity.
- **Cloud Broker:** Manages cloud services for consumers, offering aggregation and value-added services.

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

## Cloud Storage Architecture
- **Front End:** User interacts with data via APIs or applications.
- **Back End:** Physical hardware, servers, and networking infrastructure.
- **Middleware:** Handles data deduplication and replication, ensuring efficiency and reliability.


# Container Basics
- **Definition:** A container is a portable software package that includes everything needed to run an application, such as configuration files, libraries, and dependencies. This ensures consistency, scalability, and cost-effectiveness.
- **Advantages:** Containers simplify the development process by providing predefined environments, reducing setup time, and ensuring applications run consistently across different platforms.

## Five-Tier Container Architecture
1. **Developer Machines**
   - **Tasks:** Image creation, testing, and accreditation.

2. **Testing and Accreditation Systems**
   - **Tasks:** Verification and validation of image contents, signing images, and sending them to a registry.

3. **Registries**
   - **Tasks:** Storing images and delivering them based on requests using orchestration software.

4. **Orchestrators**
   - **Tasks:** Transforming images into containers and deploying them to the hosts.

5. **Hosts**
   - **Tasks:** Operating and managing containers as instructed by the orchestrator.

## Key Terms and Concepts
- **Docker:** A popular open-source platform for building, deploying, and managing containerized applications.
  - **Docker Daemon:** Background service managing Docker objects.
  - **Docker Client:** Primary interface for users to interact with Docker.
  - **Docker Registry:** Repository of official and user-contributed images, e.g., Docker Hub.
  - **Dockerfile:** A text file with instructions to build a Docker image.

## Container Orchestration
- **Definition:** Automation of the container lifecycle, including provisioning, configuring, deploying, securing, monitoring, resource allocation, and scaling.
- **Tools:** Kubernetes, OpenShift, Ansible, Docker Swarm.

## Security Concerns
- **Public Containers:** Ensure third-party containers are secure before using them.
- **Vulnerabilities:** Regularly update software to avoid security breaches.
- **Container Breakout:** Prevent attackers from accessing the host system.
- **Insecure Storage:** Securely store API keys, usernames, and passwords.
- **Resource Exhaustion:** Prevent noisy neighbor attacks that exhaust system resources.

# Hacking Cloud Services

## Cloud Vulnerability Scans
- **Definition**: Automated tools to discover vulnerabilities specifically in cloud environments.

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
- **Objective**: Identify open S3 buckets to uncover sensitive information (e.g., AWS keys, usernames, passwords).
- **Common Tools**:
   - **Grey Hat Warfare**: Web-based tool to search for publicly accessible S3 buckets.
   - **S3 Scanner**: Command-line tool for scanning S3 buckets.
   - **Bucket Kicker**: Script to identify and analyze open S3 buckets.

## AWS Enumeration
- **Purpose**: Identify misconfigurations and vulnerabilities in AWS roles, permissions, and services.
- **Techniques**:
   - **AWS CLI**: Command-line interface to query IAM roles, permissions, and access keys.
   - **Pacu**: Framework for pentesting AWS environments, automating the discovery of misconfigurations.
   - **Cloud Goat**: Tool to create an intentionally vulnerable AWS environment for testing.

# Cloud Security Controls Overview

## Introduction
Cloud security controls are mechanisms put in place to secure cloud systems, ensuring they are protected from various threats. These controls can be standard (traditional) or cloud-specific.

## Standard Security Controls
These controls are not exclusive to cloud environments but are essential for securing any IT infrastructure.

1. **Software Development Lifecycle (SDLC)**
   - Ensure secure development practices to prevent vulnerabilities.
   - Example: Preventing AWS credential leaks.

2. **Patches and Updates**
   - Regularly update and patch systems to close security gaps.
   - Example: Keeping the operating system and applications updated.

3. **Changing Defaults**
   - Always change default settings, such as passwords, to prevent unauthorized access.

4. **Firewalls, IDSs, IPSs, and WAFs**
   - Implement these to monitor and block malicious activities.

5. **Logging and Monitoring**
   - Perform continuous logging and monitoring to detect and respond to anomalies.

6. **Denial of Service (DoS) Protection**
   - Use tools to mitigate DoS and Distributed DoS attacks.

7. **Encryption**
   - Encrypt data to protect it in transit and at rest.

8. **Antivirus and Endpoint Protection**
   - Use antivirus software and endpoint detection and response (EDR) solutions.

## Cloud-Specific Security Controls
These controls are tailored for cloud environments and address unique cloud security challenges.

1. **S3 Bucket Policies**
   - Configure permissions carefully to control access to S3 buckets.
   - Example: AWS S3 policies to restrict or allow access.

2. **Docker Security Practices**
   - Use trusted Docker images and follow security best practices.
   - Examples:
     - Keep Docker updated.
     - Limit container capabilities.
     - Use static analysis tools like Trivy.

3. **Kubernetes Security Practices**
   - Apply security measures specific to Kubernetes environments.
   - Examples:
     - Restrict access to the Kubernetes API.
     - Use namespaces and network policies.
     - Regularly review and audit security settings.

## Security Tools
Several tools can help with assessing and improving cloud security.

1. **Qualys**
   - Provides a cloud platform for vulnerability scanning.

2. **Prisma Cloud (Palo Alto Networks)**
   - Offers comprehensive cloud-native application protection.

3. **Aqua Security**
   - Focuses on container security and cloud-native environments.

4. **Tenable**
   - Well-known for its vulnerability management solutions.

5. **Kubebench (GitHub)**
   - An open-source tool that checks Kubernetes deployments against CIS benchmarks.

6. **Sumo Logic**
   - Provides cloud-native SaaS analytics for security and observability.
