// qr_login_manager.go
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"golang.org/x/crypto/pbkdf2"
	"github.com/skip2/go-qrcode"
)

const (
	keyLength = 32
	saltSize  = 16
	nonceSize = 12
	iter      = 100000
)

func deriveKey(password, salt []byte) []byte {
	return pbkdf2.Key(password, salt, iter, keyLength, sha256.New)
}

func encryptData(data []byte, password string) ([]byte, error) {
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	key := deriveKey([]byte(password), salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ciphertext := aesgcm.Seal(nil, nonce, data, nil)
	return append(append(salt, nonce...), ciphertext...), nil
}

func decryptData(encrypted []byte, password string) ([]byte, error) {
	if len(encrypted) < saltSize+nonceSize {
		return nil, fmt.Errorf("invalid encrypted data")
	}
	salt := encrypted[:saltSize]
	nonce := encrypted[saltSize : saltSize+nonceSize]
	ciphertext := encrypted[saltSize+nonceSize:]
	key := deriveKey([]byte(password), salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aesgcm.Open(nil, nonce, ciphertext, nil)
}

type BackupData struct {
	Created string   `json:"created"`
	Codes   []string `json:"codes"`
}

func generateCodes(count int, length int) []string {
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	codes := make([]string, count)
	b := make([]byte, length)
	for i := 0; i < count; i++ {
		for j := range b {
			idx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
			b[j] = chars[idx.Int64()]
		}
		codes[i] = string(b)
	}
	return codes
}

func saveToFile(data BackupData, password, filename string) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}
	enc, err := encryptData(jsonData, password)
	if err != nil {
		return err
	}
	return os.WriteFile(filename, enc, 0644)
}

func loadFromFile(filename, password string) (BackupData, error) {
	enc, err := os.ReadFile(filename)
	if err != nil {
		return BackupData{}, err
	}
	dec, err := decryptData(enc, password)
	if err != nil {
		return BackupData{}, err
	}
	var data BackupData
	err = json.Unmarshal(dec, &data)
	return data, err
}

func listCodes(filename, password string) error {
	data, err := loadFromFile(filename, password)
	if err != nil {
		return err
	}
	fmt.Printf("Backup: %s\n", filename)
	fmt.Printf("Created: %s\n", data.Created)
	fmt.Println("Codes:")
	for _, code := range data.Codes {
		fmt.Printf("  %s\n", code)
	}
	return nil
}

func generateQR(filename, password, output string) error {
	data, err := loadFromFile(filename, password)
	if err != nil {
		return err
	}
	codesStr := ""
	for i, c := range data.Codes {
		if i > 0 {
			codesStr += "\n"
		}
		codesStr += c
	}
	return qrcode.WriteFile(codesStr, qrcode.Medium, 256, output)
}

func checkCode(filename, password, code string) error {
	data, err := loadFromFile(filename, password)
	if err != nil {
		return err
	}
	for _, c := range data.Codes {
		if c == code {
			fmt.Printf("Code '%s' is valid (found in backup).\n", code)
			return nil
		}
	}
	fmt.Printf("Code '%s' is NOT in backup.\n", code)
	return nil
}

func main() {
	var (
		genCount   int
		outputFile string
		password   string
		listFile   string
		qrFile     string
		checkCode  string
	)
	flag.IntVar(&genCount, "generate", 0, "Generate backup codes")
	flag.StringVar(&outputFile, "output", "", "Output file for encrypted backup")
	flag.StringVar(&password, "password", "", "Password")
	flag.StringVar(&listFile, "list", "", "List codes from file")
	flag.StringVar(&qrFile, "qr", "", "Generate QR from file")
	flag.StringVar(&checkCode, "check", "", "Check code in backup")
	flag.Parse()

	if genCount > 0 {
		if outputFile == "" || password == "" {
			fmt.Fprintln(os.Stderr, "Error: --output and --password required for generation")
			os.Exit(1)
		}
		codes := generateCodes(genCount, 8)
		data := BackupData{Created: time.Now().UTC().Format(time.RFC3339), Codes: codes}
		if err := saveToFile(data, password, outputFile); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Saved encrypted backup to %s\n", outputFile)
	} else if listFile != "" {
		if password == "" {
			fmt.Fprintln(os.Stderr, "Error: --password required")
			os.Exit(1)
		}
		if err := listCodes(listFile, password); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	} else if qrFile != "" {
		if password == "" || outputFile == "" {
			fmt.Fprintln(os.Stderr, "Error: --password and --output required for QR")
			os.Exit(1)
		}
		if err := generateQR(qrFile, password, outputFile); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("QR code saved to %s\n", outputFile)
	} else if checkCode != "" {
		if listFile == "" || password == "" {
			fmt.Fprintln(os.Stderr, "Error: --list and --password required for check")
			os.Exit(1)
		}
		if err := checkCode(listFile, password, checkCode); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	} else {
		fmt.Println("Use --help for usage.")
	}
}
