# Crypto Gronsfeld

A secure, Go-based implementation of the **Gronsfeld Cipher** combined with **FNV-1a hashing** for data integrity. This project demonstrates the industry-standard **Encrypt-then-MAC** (Message Authentication Code) architecture to ensure that data is not only hidden but mathematically proven to be untampered with in transit.

## The Algorithms Explained

This tool utilizes a two-step cryptographic pipeline to secure messages:

### 1. The Gronsfeld Cipher (Encryption)
The Gronsfeld cipher is a classical substitution cipher, acting as a numeric variant of the Vigenère cipher. Instead of using a keyword made of letters, it uses a key made of digits (0-9).

* **How it works:** Each letter in the plaintext is shifted forward in the alphabet by the number specified in the corresponding position of the numeric key.
* **Math:** `Ciphertext_i = (Plaintext_i + Key_i) mod 26`
* **Example:** * Plaintext: `HELLO`
  * Key: `314` (Repeats as `31431`)
  * Ciphertext: `KFOOP`

### 2. FNV-1a (Data Integrity / MAC)
To prevent tampering, the ciphertext is hashed using the Fowler–Noll–Vo (FNV-1a) algorithm. FNV-1a is a fast, non-cryptographic hash that relies on bitwise XOR and prime multiplication to create a massive avalanche effect.

* **The Constants:** It uses an Offset Basis (`2166136261`) and an FNV Prime (`16777619`).
* **The Operation:** For every byte in the data, it XORs the byte into the hash, and then multiplies by the FNV prime.

---

## The Architecture: Encrypt-then-MAC

This project strictly adheres to the **Encrypt-then-MAC** workflow to prevent Cryptographic Doom (where a system processes malicious data before verifying its authenticity). 

The system is split into two distinct pipelines:

### The Sender (Sign & Transmit)
1. **Encrypt:** The plaintext is encrypted using the Gronsfeld Cipher and the numeric key.
2. **Sign:** The ciphertext is combined with a local "Shared Secret" and hashed via FNV-1a.
3. **Package:** The Ciphertext and the Hash are sent over the network separated by a delimiter (`CIPHERTEXT|HASH`). The keys are *never* transmitted.

### The Receiver (Verify & Decrypt)
1. **Verify FIRST:** The receiver combines the incoming ciphertext with their own local Shared Secret and runs FNV-1a. If the resulting hash does not match the attached hash, the payload is instantly dropped as tampered/forged.
2. **Decrypt LAST:** If the hashes match perfectly, the ciphertext is decrypted back into the original plaintext.

---

