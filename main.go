package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"unicode"
)

// --- 1. CORE ALGORITHMS ---

func fnv1a(data string) uint32 {
	const offsetBasis uint32 = 2166136261
	const fnvPrime uint32 = 16777619

	hash := offsetBasis
	for _, b := range []byte(data) {
		hash ^= uint32(b)
		hash *= fnvPrime 
	}
	return hash
}

func processGronsfeld(text string, numericKey string, encrypt bool) string {
	var result strings.Builder
	text = strings.ToUpper(text)
	keyLen := len(numericKey)
	keyIndex := 0

	for _, char := range text {
		if unicode.IsLetter(char) {
			shift := int(numericKey[keyIndex%keyLen] - '0')
			if !encrypt {
				shift = -shift 
			}

			base := int('A')
			shiftedChar := rune((int(char) - base + shift + 26) % 26 + base)
			result.WriteRune(shiftedChar)
			keyIndex++
		} else {
			result.WriteRune(char) 
		}
	}
	return result.String()
}

// --- 2. SENDER PIPELINE (Encrypt-then-MAC) ---

func generateSecurePayload(plaintext, gronsfeldKey, sharedSecret string) string {
	ciphertext := processGronsfeld(plaintext, gronsfeldKey, true)
	signatureData := sharedSecret + ciphertext
	mac := fnv1a(signatureData)
	return fmt.Sprintf("%s|%d", ciphertext, mac)
}

// --- 3. RECEIVER PIPELINE (Verify-then-Decrypt) ---

func verifyAndDecryptPayload(payload, gronsfeldKey, sharedSecret string) (string, error) {
	parts := strings.Split(payload, "|")
	if len(parts) != 2 {
		return "", errors.New("malformed payload: missing delimiter")
	}
	
	receivedCiphertext := parts[0]
	receivedMACStr := parts[1]

	expectedSignatureData := sharedSecret + receivedCiphertext
	calculatedMAC := fnv1a(expectedSignatureData)

	receivedMAC, err := strconv.ParseUint(receivedMACStr, 10, 32)
	if err != nil {
		return "", errors.New("malformed payload: invalid MAC format")
	}

	if uint32(receivedMAC) != calculatedMAC {
		return "", errors.New("authentication failed: payload tampered or forged")
	}

	plaintext := processGronsfeld(receivedCiphertext, gronsfeldKey, false)
	return plaintext, nil
}

// --- 4. EXECUTION (CLI) ---

func main() {
	// Define command-line flags
	mode := flag.String("mode", "demo", "Mode: 'demo', 'send', or 'receive'")
	msg := flag.String("msg", "DEPLOY TO PRODUCTION", "Plaintext message (for 'send'/'demo') or payload (for 'receive')")
	key := flag.String("key", "31415", "Numeric Gronsfeld key")
	secret := flag.String("secret", "backend_microservice_token_v1", "Shared secret for MAC")
	
	flag.Parse()

	// Quick validation to ensure the key is purely numeric
	if _, err := strconv.Atoi(*key); err != nil {
		fmt.Println("Error: Gronsfeld key must be purely numeric.")
		os.Exit(1)
	}

	switch strings.ToLower(*mode) {
	case "demo":
		runDemo(*msg, *key, *secret)
	case "send":
		payload := generateSecurePayload(*msg, *key, *secret)
		fmt.Printf("%s\n", payload)
	case "receive":
		decryptedMessage, err := verifyAndDecryptPayload(*msg, *key, *secret)
		if err != nil {
			fmt.Printf("REJECTED: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("SUCCESS: %s\n", decryptedMessage)
	default:
		fmt.Println("Invalid mode. Use 'demo', 'send', or 'receive'.")
		flag.Usage()
		os.Exit(1)
	}
}

// runDemo encapsulates the original hardcoded test scenario
func runDemo(originalMessage, gronsfeldKey, sharedSecret string) {
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
	tamperedPayload := "GFQOOY UP QUTGWFWKPP|2856108169" 
	
	_, err = verifyAndDecryptPayload(tamperedPayload, gronsfeldKey, sharedSecret)
	if err != nil {
		fmt.Printf("EXPECTED REJECTION: %v\n", err)
	}
}