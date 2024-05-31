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
