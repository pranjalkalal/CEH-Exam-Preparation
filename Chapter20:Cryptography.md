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

## Cipher

- **Ciphers are algorithms used to encrypt or decrypt data.**
- **2 Types of cipher**
  - **1.Classical cipher**
      -Substitution and Transposition Ciphers
  - **2.Modern Cipher**
      -Key-Based and Input based cipher
  - **cipher modes of operation**
    - **1.electronic code book mode (ECB)**
    - **2.cipher block chaning mode (CBC)**
    - **3.cipher feedback mode(CFB)**
    - **4.counter mode**   
    
## Symmetric Algorithms

## *Symmetric Algorithms with block cipher*

## DES , Triple DES , AES

- **DES (Data Encryption Standard):** Adopted in 1977, officially retired in 2005. It’s still used in some industries, particularly the payment card industry.
  - It uses 64 bit secret key in which 56 bits are generated randomly and 8 bits for error detection.
  - it is archetypal block cipher
  
- **Triple DES:** An extension of DES, but with enhanced security. It’s being prohibited after 2023.
  - perform DES 3 time with 3 different secret keys

- **AES(Advanced encryption standard):** It has 128 bit block size with key size 128,192 and 256 bits.
  - used for both s/w and h/w.
  - it works simultaneously at multiple network layers.

- **RC5**: fast S.K block cipher for RSA security.
  - Block size can be 32,64,128 bits.
  - range of rounds can vary from 0-255.
  - size of key can vary from 0-2040 bits
 
- **RC6**: derived from RC5.
  - use 4 bit working registers rather than 2 bit registers
  - do integer multiplication.
 
- **Blowfish:** Utilized in password protection tools to e-commerce website s for securing payments.
  - designed to replace DES and IDEA algorithm.
  - rounds are 16
  - block size 64 bits
  - key ranging from 32-448 bits

- **Twofish:** 128 bit cipher, not working fast for cpu/hardware but works flexible for network based applications.

- **Threefish:** it is part of skein algo, and was enrolled in NIST's SHA-3 contest.
  - block and key sizes are equal.
  - involve 3 operations:ARX(addition,rotation,XOR)

- **Serpent:** finalized in AES contest just like blowfish.
  - use 128 bit block size
  - key size 128,192,256 bits
  - 32 rounds

- **TEA:** tiny encryption algorithm
  - rounds called cycles here.
  - 128 bits key size
  - 64 bit block
  - 232 golden ratio

- **CAST-128:** also called CAST5, having classical 12 or 16 round feistel network.
  - block size 64 bits
  - key size 40-128 bits
  - used as default cipher in GPG and PGP.
  - CAST-256 is extention of CAST-128 with 128 bit block size and key size 128-256 bits and uses zero correlation cryptanalysis.

- **GOST:** also called Magma, it's governmant standerd
  - 32 round feistel network
  - 64 bit block size
  - 256 bit key size
  - kuznyechik is latest extension of GOST.uses 128 bit block size.
    
- **Camellia:** uses key whitening technique for increased security.
  - part of TLS protocol, which is used to deliver secure communication.
  - use smaller key size of 128 bit thus making it safer cipher
  - offer high security and it's processing skills are equivalent to those of AES.
    
## *Symmetric Algorithms with stream cipher*

- **RC4**: It enables safe communication such as traffic encryption (for secure websites) and for websites that use SSL protocol.
 
## Asymmetric Algorithms
- **RSA(Rivest–Shamir–Adleman):** Uses a pair of keys (public and private). It is widely used for secure data transmission.

**Diffie-Hellman:** Another key exchange algorithm that allows secure sharing of cryptographic keys.

**YAK:** public key based authenticated exchange (AKE) protocol.
  - it requires PKI to distribute authentic public keys.
  - YAK is variant of 2 pass HMQV protocol using ZKP for proving knowledge of ephemeral secret keys from both parties.
    
## Hashing Algorithms
### Message digest functions
  - called one-way hash function
  - algorithms:MD5 and SHA
- **MD:** Commonly used to verify data integrity. Though simple, it is still useful for non-critical applications.
  - MD2-MD3-MD4-MD5-MD6
  - MD4 & MD5 is not collision resistant so better to use latest algo. like MD6,SHA-2 & SHA-3.
  - MD6 uses Merkle tree like structure.
  - tool: onlinemd5 for MD5,SHA-1 and SHA-256
 
- **SHA (Secure Hash Algorithms):** SHA-1,SHA-2(SHA-256 & SHA-512),SHA-3
  - *SHA-1:* 160 bit digest from message with max length 264-1 bits its resemble the MD5 algorithm.
  - *SHA-2:* family of 2 similar functions with different block sizes, namely SHA-256, which uses 32 bits words and SHA-512 which uses 64-bit words.
  - *SHA-3:* it uses sponge construction in which message blocks are XORed into initial bits of the state which is then invertibly permuted.

### Other Hashing Algorithms
- **RipeMD, HMAC:** Other notable hashing algorithms used in various applications for ensuring data integrity.
  - Race integrity primitives evaluation message digest (RIPMD) and hash message authentication code (HMAC)
  - 3 way MAC works: encrypt then MAC (EtM),Encrypt and MAC (E&M),MAC then Encrypt (MtE).
- **CHAP:** Challenge handshake authentication protocol used by point to point protocol (ppp) servers to validate identity of remote client or network host.
  - provide protection against replay attack.
- **EAP:** Extensible authentication protocol
  - designed for point to point connections.
  - alternative to CHAP and PAP authentication protocol.

## Digital Signatures
Digital signatures use a combination of encryption and hashing. They ensure that a message:
- Comes from a verified sender (using the sender’s private key).
- Has not been altered (using a hashing algorithm like MD5 or SHA).

## Hardware-Based Encryption
- **TPM (Trusted Platform Module):** A hardware chip that stores cryptographic keys and enhances security for features like BitLocker.
- **USB Encryption:** Keys stored on a USB drive, used for secure data access.
- **HSM (Hardware Security Module):** A device for managing digital keys, providing both physical and logical protection.
- **Hard drive encryption:** where data stored in h/w can be encrypted using a wide range of encryption options.

## Advanced Encryption Concepts
### Quantum Encryption
- Quantum encryption leverages quantum mechanics to enhance cryptographic security.
- use Quantum key distribution (QKD)
- encrypted ny sequance of photons
- evesdrop possible but manipulate not.

### Elliptic Curve Cryptography (ECC)
- ECC uses advanced algebraic equations to create shorter keys, enhancing efficiency without compromising security.
- avoid lager cryptographic key usage.
- replacement for RSA algorithm.

### Homomorphic Encryption
- Allows encrypted data to be processed without needing to decrypt it first, ensuring data remains secure even during processing.
- same key holder for encryption and decryption

## Application of Cryptography
- **BlockChain:** referred to as distributed ledger technology(DLT)
- *4 Types:*
  - 1.Public blockchain
  - 2.Private blockchain
  - 3.Federated blockchain
  - 4.Hybrid Blockchain

# Tools

### MD5-MD6 Hash calculator
- *MD5 calculator, HashMyFile, HashCalc, MD6 hash generator, md5 hash calculator, message digester*
### Hash calculator for mobile
- *Hash tools, Hash droid*
### Crptography tools
- *BCTextEncoder, AxCrypt, Microsoft cryptography tools,concealer,sensiguard,challenger*
### Cryptography Tools for Mobile
- *Secret Space Encryptor, secure Everything*
  
# Public Key Infrastructure (PKI)

### Introduction to PKI
- **Definition**: Public Key Infrastructure (PKI) involves generating, creating, distributing, managing, and revoking digital certificates.
- **Components**: Certificate management system, digital certicicates, validation authority, certification authority, end user, registration authority.
  - *Certificate management system*: Generates,distributes, stores and verifies certificate.
  - *digital certicicates*: establish credentials of person when performing online transaction.
  - *VA*: stores certificate with their public keys.
  - *CA*: issues and verifies digital certificates.(comodo,IdenTrust,DigiCert CertCentral, Godaddy,)
  - *end user*: requests,manages and user certificate.
  - *RA*: acts as the verifier for CA

### PKI Processes
- *Subject (user,company) applies for certificate to registation authority.*
- *RA receive request and verify identity then request to CA to issue public key certificate to user*
- *CA issue certificate bind subject's identity with subject's public key then send it to VA*
- *when a user makes transaction, the user duly signs the message digitally using the public key certificate and send the message to client*
- *client verify authenticity of user by inquiring with the VA about the validity of user's public key certificate*
- *VA compares the public key certificate of the user with that of the updated information provided by the CA and determines the result(valid or invalid).*

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

## Email Encryption

- **Digital Signature:** it uses asymetric cryptography for authentication and hash function for integrity.
  - *process:* sign-seal-deliver-accept-open-verify
- **Secure socate layer(SSL):** it is application layer protocol.
  - It uses RSA asymmetric encryption to encrypt data transfered over SSL connection.
  - It offers channel security with 3 properties : private channle , Authenticated channle and reliable channle.  
- **Transport layer Protocol(TLS):** to establish a secure connection between a client and server.
  - It uses RSA algorithm with 1024 and 2048 bit strengths.
  - TLS has 2 layers: TLS Record Protocol, TLS Handshake protocol.
- **cryptography Toolkits**: OpenSSL(SSL v2/v3,TLS v1,x.509 certificates,CSRs and CRLs),Keyczar,wolfSSL,AES Crypto toolkit,RELIC,PyCrypto.
- **PGP (Pretty Good Privacy)**: It provides authentication and cryptographic privacy.  
  - often used for data compression, digital signing,encry,decry.
  - It combines best feture of both conventional and public key cryptography and is there for known as hybrid cryptosystem. 
    
- **GPG (GNU Privacy Guard)**: An open-source alternative to PGP, also called hybrid encryption software as it use both symmetric and asymmetric crypto.
  - support A/MIME and Secure Shell(SSH).
    
- **Web of Trust(WOT):** it is trust model of PGP,OpenPGPand GPG.
  - It is chain of network in which individuals intermediately validate each other's certificate using their certificate.
  - every user in the network has ring of public key.
- **Email encryption Tools:** RMail, Virtru,ZixMail,Paunox,Proofpoint email protection, Egress secure email and file.

## DISk Encryption
- **Confidentiality:** privacy,passphrase,hidden volumes.
- **Encryption:** Volume encryption.
- **Protection:** USB Flash Drive,External HDD,Backup.
- **D.Encryption Tools for windows:** VeraCrypt(on-the-fly-encrypted volume),Rohos Disk encryption,Bitlocker drive encryption(uses Trusted platform module-TPM), FinalCrypt,FileVault,Broadcom Encryption,Gillsoft Full Disk encryption,Check point full disk
- **D.encryption Tools for Linux** Cryptsetup(based on DMCrypt kernel Module),eCryptfs,cryptmount,Tomb,CryFS,GnuPG
- **D.Encryption Tools for macOS:** File Vault 2(utilizes XTS-AES-128 encryption technology),VeraCrypt,Sophos safeguard encryption,Best crypt volume encryption for Mac, Broadcom symantec endpoint encryption,Rohos logon key for mac.
  
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
     
4. **Quantum Method**:
    - use shor's quantum factoring algorith on public key cryptography algorithms such as RSA and ECDH.

## Code Breaking Techniques
1. **Brute Force Attack**:
   - Systematically tries all possible keys until the correct one is found.
   - Extremely time-consuming.

2. **Frequency Analysis**:
   - Analyzes the frequency of letters or groups of letters in the ciphertext.
   - Used to break substitution ciphers by matching frequencies to known patterns.
     
3. **Trickery and Deceit:** involves the use of social engineering techniques to extract cryptography keys.

4. **One-Time Pad:** It contains many non repeating group of letters or number keys,which are chosen randomly.

## Cryptography Attack Types

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

7. **Birthday Attack**: it is class of brute force attack.
   - Birthday paradox: probability that 2 or more people in group of 23 share the same birthday is greater than 0.5

## Tools for Cryptanalysis
- **Crack Station**: An online tool for cracking hashed passwords.
   - Supports various hash types including MD5, SHA-1, and others.
- CryptTool,Cryptosense,RsaCtfTool,Msieve,Cryptol,CryptoBench

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
