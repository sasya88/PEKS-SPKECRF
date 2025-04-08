# PEKS & SPKE-CRF Java Implementation (Using JPBC)

This project implements two searchable encryption schemes:
- **PEKS**: Public Key Encryption with Keyword Search
- **SPKE-CRF**: Searchable Public-Key Encryption with Cryptographic Reverse Firewalls

Both are implemented in Java using the **JPBC (Java Pairing-Based Cryptography)** library.

---
## Authors 
1. @Sasya88
2. @Jyothi-CY

---
## Dependencies

- Java 8 or above
- JPBC Library 2.0.0

---

## JPBC Setup Instructions

1. **Download the JPBC Library**  
   ➤ https://sourceforge.net/projects/jpbc

2. **Extract Required JARs**  
   Copy the following JAR files from the `lib/jars/` directory in the JPBC repo into your project’s `lib/` folder:
   - `jpbc-api-2.0.0.jar`
   - `jpbc-crypto-2.0.0.jar`
   - `jpbc-plaf-2.0.0.jar`

---

## How to Compile and Run

### PEKSJPBCS.java
1. javac -cp "./lib/jpbc-api-2.0.0.jar;./lib/jpbc-plaf-2.0.0.jar;." PEKSJPBCS.java
2. java -cp "./lib/jpbc-api-2.0.0.jar;./lib/jpbc-plaf-2.0.0.jar;." PEKSJPBCS
### SPKECRF.java
1. javac -cp "./lib/jpbc-api-2.0.0.jar;./lib/jpbc-plaf-2.0.0.jar;." SPKECRF.java
2. java -cp "./lib/jpbc-api-2.0.0.jar;./lib/jpbc-plaf-2.0.0.jar;." SPKECRF

---
### Features
### PEKS.java
1. Keyword Encryption

2. Search Trapdoor Generation

3. Keyword Guessing Attack Simulation

### SPKECRF.java
1. Keyword Encryption with Re-Randomization

2. Secure Trapdoor Re-Randomization

3. Resistance to Keyword Guessing Attacks

#### Paper Reference
This project is based on the paper:
"Searchable Public-Key Encryption With Cryptographic Reverse Firewalls for Cloud Storage"
IEEE Transactions on Cloud Computing, 2023
