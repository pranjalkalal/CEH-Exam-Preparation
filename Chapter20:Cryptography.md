# Cryptography Basics

## Introduction
- Cryptography involves high-level mathematics used for securing data.
- It is essential in various security practices like TLS, SSL, SSH, and email encryption.
- Encryption protects data in three states: in use, in transit, and at rest.

## Key Concepts
### Encryption
- **Symmetric Encryption**: Uses a single key for both encryption and decryption. 
  - Strength: High.
  - Challenge: Securely sharing the key.
- **Asymmetric Encryption**: Uses a pair of keys (public and private).
  - Public Key: Shared openly.
  - Private Key: Kept secret.
  - Usage: The other side of communication encrypts with my public key and then I decrypt with my private key. 

### Hashing
- **Purpose**: Obfuscate data (like passwords) using algorithms.
- **Common Algorithms**: MD5, SHA-256, SHA-512.
- **Usage**: Hashes are one-way functions used to verify data integrity.

## Ciphers
### Key-Based Ciphers
- **Private Key (Symmetric)**: Same key for encryption and decryption.
- **Public Key (Asymmetric)**: Pair of public and private keys.

### Input-Based Ciphers
- **Block Ciphers**: Encrypt data in fixed-size blocks.
  - Examples: AES, Blowfish, Triple DES.
  - Characteristics: Strong but slower. it uses an initialization vector and encrypts a block then it uses the encryption of that block to encrypt the next one (Block chaining).
- **Stream Ciphers**: Encrypt data one byte at a time.
  - Example: RC4.
  - Characteristics: Faster but generally less secure than block ciphers.

### Substitution vs Transposition Ciphers
- **Substitution Cipher**: Replaces each letter with another.
  - Example: Caesar Cipher.
- **Transposition Cipher**: Rearranges the positions of letters.
  - Example: Rail Fence Cipher.

## Government Access to Keys (GAK)
- Governments may require access to encryption keys to monitor communications.
- Keys are securely stored and can be accessed with a court order.

## Tools
- **SSH Key Generation**: Create public and private keys using tools like `ssh-keygen`.
- **OpenSSL**: Tool for generating keys and implementing various ciphers.

# Crypto Algorithms and Implementations

## Symmetric Algorithms
### DES and Triple DES
- **DES (Data Encryption Standard):** Adopted in 1977, officially retired in 2005. It’s still used in some industries, particularly the payment card industry.
- **Triple DES:** An extension of DES, but with enhanced security. It’s being prohibited after 2023.

### RC Algorithms
- **RC4, RC5, RC6:** These are symmetric key algorithms, each iteration being more secure than the previous one. RC4 is notably used in Kerberos.

### AES (Advanced Encryption Standard)
- **AES:** A widely used symmetric algorithm, known for its strength and efficiency.

### Blowfish
- **Blowfish:** Utilized in secure email encryption tools, backup software, and password management systems.

## Asymmetric Algorithms
### RSA (Rivest–Shamir–Adleman)
- **RSA:** Uses a pair of keys (public and private). It is widely used for secure data transmission.

### Diffie-Hellman
- **Diffie-Hellman:** Another key exchange algorithm that allows secure sharing of cryptographic keys.

## Hashing Algorithms
### MD5 and SHA
- **MD5:** Commonly used to verify data integrity. Though simple, it is still useful for non-critical applications.
- **SHA (Secure Hash Algorithms):** Includes SHA-1, SHA-256, and SHA-512. Higher numbers indicate more complexity and security. SHA-256 is the current standard.

### Other Hashing Algorithms
- **RipeMD, HMAC:** Other notable hashing algorithms used in various applications for ensuring data integrity.

## Digital Signatures
Digital signatures use a combination of encryption and hashing. They ensure that a message:
- Comes from a verified sender (using the sender’s private key).
- Has not been altered (using a hashing algorithm like MD5 or SHA).

## Hardware-Based Encryption
- **TPM (Trusted Platform Module):** A hardware chip that stores cryptographic keys and enhances security for features like BitLocker.
- **USB Encryption:** Keys stored on a USB drive, used for secure data access.
- **HSM (Hardware Security Module):** A device for managing digital keys, providing both physical and logical protection.

## Advanced Encryption Concepts
### Quantum Encryption
- Quantum encryption leverages quantum mechanics to enhance cryptographic security.

### Elliptic Curve Cryptography (ECC)
- ECC uses advanced algebraic equations to create shorter keys, enhancing efficiency without compromising security.

### Homomorphic Encryption
- Allows encrypted data to be processed without needing to decrypt it first, ensuring data remains secure even during processing.


# Cryptography Tools

### Introduction to Cryptography Tools
- **PGP (Pretty Good Privacy)**: A standard encryption mechanism, originally open-source, now owned by Broadcom Inc.
- **GPG (GNU Privacy Guard)**: An open-source alternative to PGP, providing similar functionalities.

### Using GPG
- **Platforms**: GPG can be used on various operating systems, including Linux, Windows (through GPG4Win), and others.
- **Basic Commands**: 
  - **Generating Keys**: `gpg --full-generate-key` to create a new key pair.
  - **Listing Keys**: `gpg --list-keys` to display all keys.
  - **Exporting Keys**: `gpg --armor --export <email>` to export a key in ASCII format.
  - **Importing Keys**: `gpg --import <keyfile>` to import a key.
  - **Encrypting Files**: 
    ```sh
    gpg --output doc.gpg --encrypt --recipient <recipient-email> doc.txt
    ```
  - **Decrypting Files**:
    ```sh
    gpg --output doc2.txt --decrypt doc.gpg
    ```

### Summary of Tools Discussed
- **GPG for Linux**: Command-line based usage for key generation, key management, encryption, and decryption.
- **GPG4Win**: A suite of tools for Windows, including Cleopatra for managing keys and GPGEX for encryption and decryption through the context menu.
- **BC Text Encoder**: A simple tool for encoding and decoding text with a password or key, although its interface may not be very user-friendly.


# Public Key Infrastructure (PKI)

### Introduction to PKI
- **Definition**: Public Key Infrastructure (PKI) involves generating, creating, distributing, managing, and revoking digital certificates.
- **Components**: Includes public keys, certificates, and the management of these elements.

### PKI Processes
- **Certificate Authority (CA)**: Issues, validates, and revokes certificates.
- **Registration Authority (RA)**: Pre-screens certificate requests and verifies requester identity before forwarding to the CA.
- **Validation Authority (VA)**: Validates digital certificates and manages the Certification Revocation List (CRL).

### Using PKI
- **Generating Certificates**: The process involves the subject (user or organization) applying for a certificate, RA verifying the request, CA issuing the certificate, and VA validating it.
- **Certificate Services**: Built into Windows Server, allowing for the management of certificates, including issuing, revoking, and handling certificate requests.

### Practical Examples
- **HTTPS Websites**: Use certificates to establish secure connections.
- **VPN Connections**: Certificates can secure VPN tunnels using IPsec.
- **User Authentication**: Systems like Windows Server and Active Directory use certificates for user and device authentication.

### Certificate Management
- **Windows Server Certificate Services**: Provides a management console to handle all certificate-related tasks, such as issuing, revoking, and managing certificate requests.
- **Third-Party CA Services**: Organizations like VeriSign and DigiCert provide globally trusted certificates stored securely to prevent compromise.

### Self-Signed Certificates
- **Usage**: Suitable for internal organization use where the entities involved trust each other.
- **Limitations**: Not ideal for public use as they are not recognized by external parties without explicit trust settings, potentially leading to security warnings.

### Summary of Key Concepts
- **Subject**: User or organization requesting a certificate.
- **CA**: Issues and manages certificates.
- **RA**: Verifies requester's identity before sending the request to the CA.
- **VA**: Validates certificates and manages revocation lists.
- **Self-Signed Certificates**: Used within trusted environments but not for public use.

# Cryptanalysis
**Cryptanalysis** is the study of cryptosystems to find exploitable weaknesses.

## Methods of Cryptanalysis
1. **Linear Method (Known Plain Text Attack)**:
   - Requires both encrypted and plaintext data.
   - Used to reverse engineer the decryption key.
   - Guessing common words or phrases can help in finding the plaintext.

2. **Differential Method (Chosen Plain Text Attack)**:
   - Attacker defines the plaintext inputs and analyzes the results.
   - Aimed at discovering the encryption key by chosen inputs and outputs.
   - Similar to linear but more controlled since the plaintext is chosen.

3. **Integral Method**:
   - A specific type of differential attack.
   - Works with larger inputs, often used in block ciphers.

## Code Breaking Techniques
1. **Brute Force Attack**:
   - Systematically tries all possible keys until the correct one is found.
   - Extremely time-consuming.

2. **Frequency Analysis**:
   - Analyzes the frequency of letters or groups of letters in the ciphertext.
   - Used to break substitution ciphers by matching frequencies to known patterns.

## Additional Attack Types
1. **Man-in-the-Middle Attack**:
   - The attacker intercepts and possibly alters the communication between two parties who believe they are directly communicating with each other.

2. **Meet-in-the-Middle Attack**:
   - Reduces the time to break ciphers using multiple keys.
   - Involves known plaintext attacks from both sides of the encryption/decryption process.

3. **Side Channel Attacks**:
   - Exploits physical characteristics of the cryptosystem such as power usage, electromagnetic emissions, or audio emanations to gain information about the cryptosystem.

4. **Hash Collisions**:
   - Occur when two different inputs produce the same hash output.
   - Dangerous because it can allow unauthorized access if a different input produces a matching hash.

5. **Related Key Attacks**:
   - Exploits relationships between keys to uncover the key or data.
   - Common in older encryption methods like WEP where keys are reused.

6. **Rubber Hose Attack**:
   - A physical attack where secrets are extracted from a person through coercion or torture.

## Tools for Cryptanalysis
- **Crack Station**: An online tool for cracking hashed passwords.
   - Supports various hash types including MD5, SHA-1, and others.


# Crypto Attack Countermeasures

## Secure Key Sharing
- Protect private information by securely sharing keys to prevent unauthorized access.
- Avoid common pitfalls like emailing keys, which can lead to compromise if intercepted.

## Symmetric vs. Asymmetric Encryption
- Symmetric algorithms are stronger but require secure key sharing.
- Asymmetric algorithms offer easier key management but may lack robust encryption.
- Combining both types of encryption enhances security.

## Encryption Strength
- Use encryption schemes with higher bit lengths for better security.
- AES 256 and RSA are recommended due to their proven track record.

## Avoiding Homegrown Encryption
- Stick to established encryption methods like AES and RSA rather than creating custom systems.
- Homegrown encryption lacks the vetting and community support of widely-used encryption standards.

## Avoid Hard-Coded Credentials
- Hard-coded keys pose a significant security risk, making it easy for attackers to reverse engineer and compromise systems.
- Encrypt keys with passwords or passphrases to add an extra layer of security.

## Intrusion Detection Systems (IDS)
- IDS can monitor key exchanges and detect suspicious activities like man-in-the-middle attacks.
- Ensure IDS systems are robust and properly vetted to avoid security vulnerabilities.

## Key Stretching
- Increase the length of keys to enhance security, similar to using longer passwords to resist brute-force attacks.
- Key stretching techniques like PBKDF2 and bcrypt strengthen encryption by making it more difficult to crack.
