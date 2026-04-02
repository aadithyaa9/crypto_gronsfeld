package main

import (
	"strings"
	"testing"
)

// TestFNV1a ensures the hashing algorithm is deterministic
func TestFNV1a(t *testing.T) {
	data := "test_string_123"
	hash1 := fnv1a(data)
	hash2 := fnv1a(data)

	if hash1 != hash2 {
		t.Errorf("Expected identical strings to produce identical hashes, got %d and %d", hash1, hash2)
	}
}

// TestProcessGronsfeld verifies the math of the cipher using the example from the README
func TestProcessGronsfeld(t *testing.T) {
	plaintext := "HELLO"
	key := "314"
	expectedCiphertext := "KFPOP"

	// Test Encryption
	ciphertext := processGronsfeld(plaintext, key, true)
	if ciphertext != expectedCiphertext {
		t.Errorf("Encryption failed. Expected %s, got %s", expectedCiphertext, ciphertext)
	}

	// Test Decryption
	decrypted := processGronsfeld(ciphertext, key, false)
	if decrypted != plaintext {
		t.Errorf("Decryption failed. Expected %s, got %s", plaintext, decrypted)
	}

	// Test with spaces and punctuation (should remain untouched)
	complexText := "HELLO WORLD!"
	complexCipher := processGronsfeld(complexText, key, true)
	if !strings.Contains(complexCipher, " ") || !strings.Contains(complexCipher, "!") {
		t.Errorf("Cipher altered spaces or punctuation: %s", complexCipher)
	}
}

// TestEndToEndPipeline tests the Encrypt-then-MAC and Verify-then-Decrypt flow
func TestEndToEndPipeline(t *testing.T) {
	originalMessage := "TOP SECRET DATA"
	gronsfeldKey := "98765"
	sharedSecret := "super_secret_token"

	// 1. Generate Payload (Sender)
	payload := generateSecurePayload(originalMessage, gronsfeldKey, sharedSecret)

	// Verify payload format
	if !strings.Contains(payload, "|") {
		t.Errorf("Payload missing delimiter: %s", payload)
	}

	// 2. Verify and Decrypt (Receiver)
	decryptedMessage, err := verifyAndDecryptPayload(payload, gronsfeldKey, sharedSecret)
	if err != nil {
		t.Fatalf("Failed to verify/decrypt valid payload: %v", err)
	}

	if decryptedMessage != originalMessage {
		t.Errorf("Decrypted message does not match original. Expected %s, got %s", originalMessage, decryptedMessage)
	}
}

// TestTamperingRejection ensures the fail-fast mechanism works
func TestTamperingRejection(t *testing.T) {
	originalMessage := "FINANCIAL RECORD"
	gronsfeldKey := "12345"
	sharedSecret := "bank_secret"

	validPayload := generateSecurePayload(originalMessage, gronsfeldKey, sharedSecret)

	// Tamper Scenario 1: Modify the ciphertext
	parts := strings.Split(validPayload, "|")
	tamperedCiphertext := parts[0] + "X"
	tamperedPayload1 := tamperedCiphertext + "|" + parts[1]

	_, err := verifyAndDecryptPayload(tamperedPayload1, gronsfeldKey, sharedSecret)
	if err == nil {
		t.Errorf("Expected error for tampered ciphertext, but payload was accepted")
	}

	// Tamper Scenario 2: Modify the MAC hash
	tamperedPayload2 := parts[0] + "|123456789"
	_, err = verifyAndDecryptPayload(tamperedPayload2, gronsfeldKey, sharedSecret)
	if err == nil {
		t.Errorf("Expected error for tampered MAC, but payload was accepted")
	}

	// Tamper Scenario 3: Malformed payload (missing delimiter)
	malformedPayload := "JUST_SOME_GARBAGE_DATA"
	_, err = verifyAndDecryptPayload(malformedPayload, gronsfeldKey, sharedSecret)
	if err == nil {
		t.Errorf("Expected error for malformed payload, but it was accepted")
	}
}