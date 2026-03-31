package main

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

// --- 1. CORE ALGORITHMS ---

// fnv1a generates a 32-bit hash using the FNV-1a algorithm.
// Reason: We iterate over raw bytes ([]byte) rather than runes to ensure 
// that character encoding (like UTF-8) doesn't cause mismatched hashes across different systems.
func fnv1a(data string) uint32 {
	const offsetBasis uint32 = 2166136261
	const fnvPrime uint32 = 16777619

	hash := offsetBasis
	for _, b := range []byte(data) {
		hash ^= uint32(b)
		hash *= fnvPrime // Relies on Go's automatic uint32 overflow for modulo 2^32
	}
	return hash
}

// processGronsfeld handles both encryption and decryption.
// Reason: We use runes to safely handle potential multi-byte characters, 
// though the cipher mathematically only shifts standard A-Z letters.
func processGronsfeld(text string, numericKey string, encrypt bool) string {
	var result strings.Builder
	text = strings.ToUpper(text)
	keyLen := len(numericKey)
	keyIndex := 0

	for _, char := range text {
		if unicode.IsLetter(char) {
			shift := int(numericKey[keyIndex%keyLen] - '0')
			if !encrypt {
				shift = -shift // Reverse the shift for decryption
			}

			base := int('A')
			// +26 ensures we don't get negative numbers during decryption
			shiftedChar := rune((int(char) - base + shift + 26) % 26 + base)
			result.WriteRune(shiftedChar)
			keyIndex++
		} else {
			result.WriteRune(char) // Leave spaces/punctuation untouched
		}
	}
	return result.String()
}

// --- 2. SENDER PIPELINE (Encrypt-then-MAC) ---

// generateSecurePayload encrypts the plaintext, signs it, and packages it.
func generateSecurePayload(plaintext, gronsfeldKey, sharedSecret string) string {
	// Step 1: Encrypt the data FIRST. 
	// Reason: We never want to expose plain text to the hashing algorithm if we can avoid it.
	ciphertext := processGronsfeld(plaintext, gronsfeldKey, true)

	// Step 2: Create the signature string by combining the Secret and the Ciphertext.
	signatureData := sharedSecret + ciphertext

	// Step 3: Hash the signature data to create the MAC (Message Authentication Code).
	mac := fnv1a(signatureData)

	// Step 4: Package the Ciphertext and the MAC using a strict delimiter "|".
	// Reason: The receiver needs a predictable structural format to parse the data.
	return fmt.Sprintf("%s|%d", ciphertext, mac)
}

// --- 3. RECEIVER PIPELINE (Verify-then-Decrypt) ---

// verifyAndDecryptPayload authenticates the payload before attempting decryption.
func verifyAndDecryptPayload(payload, gronsfeldKey, sharedSecret string) (string, error) {
	// Step 1: Parse the network payload.
	parts := strings.Split(payload, "|")
	if len(parts) != 2 {
		return "", errors.New("malformed payload: missing delimiter")
	}
	
	receivedCiphertext := parts[0]
	receivedMACStr := parts[1]

	// Step 2: Reconstruct the signature data using the local Shared Secret.
	expectedSignatureData := sharedSecret + receivedCiphertext

	// Step 3: Calculate the expected MAC.
	calculatedMAC := fnv1a(expectedSignatureData)

	// Step 4: Compare hashes (Authentication).
	// Reason: This is the "Fail-Fast" mechanism. If the data was tampered with, 
	// the hashes mismatch, and we abort immediately to prevent Cryptographic Doom.
	receivedMAC, err := strconv.ParseUint(receivedMACStr, 10, 32)
	if err != nil {
		return "", errors.New("malformed payload: invalid MAC format")
	}

	if uint32(receivedMAC) != calculatedMAC {
		return "", errors.New("authentication failed: payload tampered or forged")
	}

	// Step 5: Decrypt the authenticated ciphertext.
	// Reason: We only spend CPU cycles running the decryption algorithm because 
	// we have mathematically proven the ciphertext is safe and intact.
	plaintext := processGronsfeld(receivedCiphertext, gronsfeldKey, false)
	return plaintext, nil
}

// --- 4. EXECUTION ---

func main() {
	// Constants established prior to communication
	gronsfeldKey := "31415" 
	sharedSecret := "backend_microservice_token_v1"

	originalMessage := "DEPLOY TO PRODUCTION"
	fmt.Printf("Original Message: %s\n\n", originalMessage)

	// --- SENDER ---
	fmt.Println("--- SENDER PHASE ---")
	payload := generateSecurePayload(originalMessage, gronsfeldKey, sharedSecret)
	fmt.Printf("Transmitted over network: %s\n\n", payload)

	// --- RECEIVER ---
	fmt.Println("--- RECEIVER PHASE ---")
	decryptedMessage, err := verifyAndDecryptPayload(payload, gronsfeldKey, sharedSecret)
	if err != nil {
		fmt.Printf("ERROR: %v\n", err)
	} else {
		fmt.Printf("SUCCESS: Decrypted payload -> %s\n", decryptedMessage)
	}

	// --- HACKER SCENARIO ---
	fmt.Println("\n--- TAMPERING SIMULATION ---")
	// A hacker intercepts the payload and changes one letter of the ciphertext
	tamperedPayload := "GFQOOY UP QUTGWFWKPP|2856108169" 
	
	_, err = verifyAndDecryptPayload(tamperedPayload, gronsfeldKey, sharedSecret)
	if err != nil {
		fmt.Printf("EXPECTED REJECTION: %v\n", err)
	}
}