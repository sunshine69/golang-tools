package utils

import (
	"archive/zip"
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	htmltemplate "html/template"
	"io"
	"io/fs"
	"log"
	"maps"
	"math"
	"math/big"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/textproto"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"text/template"
	"time"
	"unicode"

	"net/smtp"

	jsoniter "github.com/json-iterator/go"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/net/publicsuffix"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
	"gopkg.in/yaml.v3"
)

// TimeISO8601LayOut
const (
	TimeISO8601LayOut     = "2006-01-02T15:04:05-0700"
	AUTimeLayout          = "02/01/2006 15:04:05 MST"
	CleanStringDateLayout = "2006-01-02-150405"
	LetterBytes           = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#%^()-,."
)

var (
	json = jsoniter.ConfigCompatibleWithStandardLibrary
)

// ArrayFlags to be used for standard golang flag to store multiple values. Something like -f file1 -f file2
// will store list of file1, file2 in the var of this type.
// Example:
//
// var myvar ArrayFlags
// flag.Var(&myvar, "-f", "", "File names")
type ArrayFlags []string

func (i *ArrayFlags) String() string {
	return "my string representation"
}
func (i *ArrayFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}

// Time handling
const (
	millisPerSecond     = int64(time.Second / time.Millisecond)
	nanosPerMillisecond = int64(time.Millisecond / time.Nanosecond)
	nanosPerSecond      = int64(time.Second / time.Nanosecond)
)

// NsToTime -
func NsToTime(ns int64) time.Time {
	secs := ns / nanosPerSecond
	nanos := ns - secs*nanosPerSecond
	return time.Unix(secs, nanos)
}

// ChunkString -
func ChunkString(s string, chunkSize int) []string {
	var chunks []string
	runes := []rune(s)

	if len(runes) == 0 {
		return []string{s}
	}
	for i := 0; i < len(runes); i += chunkSize {
		nn := i + chunkSize
		if nn > len(runes) {
			nn = len(runes)
		}
		chunks = append(chunks, string(runes[i:nn]))
	}
	return chunks
}

func GenerateLinuxRandom(max uint64) (uint64, error) {
	f, err := os.Open("/dev/random")
	if err != nil {
		return 0, fmt.Errorf("failed to open /dev/random: %w", err)
	}
	defer f.Close()

	reader := bufio.NewReader(f)

	limit := (math.MaxUint64 / max) * max
	for {
		var b [8]byte
		if _, err := reader.Read(b[:]); err != nil {
			return 0, fmt.Errorf("failed to read from /dev/random: %w", err)
		}
		num := uint64(binary.BigEndian.Uint64(b[:]))

		if num < limit {
			return uint64(num % max), nil
		}
	}
}

// GenerateRandom geenrate random number directly using /dev/ramdom rather than crypto lib
// Only support on Linux. On other platform it will call other func to use crypto lib
func GenerateRandom(max uint64) uint64 {
	if runtime.GOOS == "linux" {
		return Must(GenerateLinuxRandom(max))
	} else {
		return uint64(MakeRandNum(int(max)))
	}
}

// MakeRandNum -
func MakeRandNum(max int) int {
	gen_number, _ := rand.Int(rand.Reader, big.NewInt(int64(max)))
	return int(gen_number.Int64())
}

func Md5Sum(key string) string {
	hasher := md5.New()
	hasher.Write([]byte(key))
	return hex.EncodeToString(hasher.Sum(nil))
}

func Sha1Sum(in string) string {
	sum := sha1.Sum([]byte(in))
	return fmt.Sprintf("%x", sum)
}

func Sha256Sum(in string) string {
	h := sha256.New()
	io.WriteString(h, in)
	return fmt.Sprintf("%x", h.Sum(nil))
}

func Sha512Sum(in string) string {
	sum := sha512.Sum512([]byte(in))
	return fmt.Sprintf("%x", sum)
}

// AES encrypt a string. Output is cipher text base64 encoded
func Encrypt(text, key string) string {
	text1 := []byte(text)
	// generate a new aes cipher using our 32 byte long key
	c, err := aes.NewCipher([]byte(Md5Sum(key)))

	if err != nil {
		fmt.Println(err)
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		fmt.Println(err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		fmt.Println(err)
	}
	encData := gcm.Seal(nonce, nonce, text1, nil)
	return base64.StdEncoding.EncodeToString(encData)
}

// AES decrypt a ciphertext base64 encoded string
func Decrypt(ciphertextBase64 string, key string) (string, error) {
	key1 := []byte(Md5Sum(key))

	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextBase64)
	if err != nil {
		return "Decode error", err
	}
	c, err := aes.NewCipher(key1)
	if err != nil {
		return "NewCipher error", err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return "NewGCM error", err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return "Unexpected size with nonce data", err
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "Decrypt error", err
	}
	return string(plaintext), nil
}

func RandomHex(n int) (string, error) {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// MakePassword -
func MakePassword(length int) string {
	b := make([]byte, length)
	const charset = `abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_-+=,[]{}|\/~:;?.`
	for i := range b {
		b[i] = charset[GenerateRandom(uint64(len(charset)))]
	}
	return string(b)
}

// GoFindExec take a directory path and list of regex pattern to match the file name. If it matches then it call the callback function for that file name.
// filetype is parsed from the directory prefix, file:// for file, dir:// for directory
func GoFindExec(directories []string, path_pattern []string, callback func(filename string) error) {
	pathPtn := []*regexp.Regexp{}
	for _, p := range path_pattern {
		pathPtn = append(pathPtn, regexp.MustCompile(p))
	}
	for _, rootdir := range directories {
		var filetype, rootdir1 string
		switch {
		case strings.HasPrefix(rootdir, `file://`):
			filetype = "f"
			rootdir1 = strings.TrimPrefix(rootdir, `file://`)
		case strings.HasPrefix(rootdir, `dir://`):
			filetype = "d"
			rootdir1 = strings.TrimPrefix(rootdir, `dir://`)
		default:
			filetype = "f"
			rootdir1 = rootdir
		}
		err1 := filepath.Walk(rootdir1, func(fpath string, info fs.FileInfo, err error) error {
			if err != nil {
				fmt.Fprintln(os.Stderr, err.Error())
				return nil
			}
			fname := info.Name()

			if (filetype == "d" && info.IsDir()) || (filetype == "f" && !info.IsDir()) {
				for _, p := range pathPtn {
					if found := p.MatchString(fname); found {
						if err := callback(fpath); err != nil {
							return err
						}
						break
					}
				}
			}
			return nil
		})
		if err1 != nil {
			panic(err1.Error())
		}
	}
}

// ReadFileToLines will read a file and return content as a slice of lines. If cleanline is true then each line will be trim and empty line will be removed
func ReadFileToLines(filename string, cleanline bool) []string {
	if datab, err := os.ReadFile(filename); err == nil {
		lines := strings.Split(string(datab), "\n")
		if !cleanline {
			return lines
		} else {
			o := []string{}
			for _, l := range lines {
				l = strings.TrimSpace(l)
				if l != "" {
					o = append(o, l)
				}
			}
			return o
		}
	} else {
		return []string{}
	}
}

func ComputeHash(plainText string, salt []byte) string {
	plainTextWithSalt := []byte(plainText)
	plainTextWithSalt = append(plainTextWithSalt, salt...)
	sha_512 := sha512.New()
	sha_512.Write(plainTextWithSalt)
	out := sha_512.Sum(nil)
	out = append(out, []byte(salt)...)
	return base64.StdEncoding.EncodeToString(out)
}

func VerifyHash(password string, passwordHashString string, saltLength int) bool {
	// log.Printf("DEBUG VerifyHash input pass: %s - Hash %s s_len %d\n", password, passwordHashString, saltLength)
	passwordHash, _ := base64.StdEncoding.DecodeString(passwordHashString)
	saltBytes := []byte(passwordHash[len(passwordHash)-saltLength:])
	result := ComputeHash(password, saltBytes)
	return result == passwordHashString
}

func MakeSalt(length int8) (salt *[]byte) {
	asalt := make([]byte, length)
	rand.Read(asalt)
	return &asalt
}

// Encrypt zip files. The password will be automtically generated and return to the caller
// Requires command 'zip' available in the system
func ZipEncript(filePath ...string) string {
	src, dest, key := filePath[0], "", ""
	argCount := len(filePath)
	if argCount > 1 {
		dest = filePath[1]
	} else {
		dest = src + ".zip"
	}
	if argCount > 2 {
		key = filePath[2]
	} else {
		key = MakePassword(42)
	}
	os.Remove(dest)
	srcDir := filepath.Dir(src)
	srcName := filepath.Base(src)
	absDest, _ := filepath.Abs(dest)

	fmt.Printf("DEBUG srcDir %s - srcName %s\n", srcDir, srcName)
	cmd := exec.Command("/bin/sh", "-c", "cd "+srcDir+"; /usr/bin/zip -r -e -P '"+key+"' "+absDest+" "+srcName)
	_, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Println(cmd.String())
		log.Fatal(err)
	}
	return key
}

// ZipDecrypt decrypt the zip file. First arg is the file name, second is the key used to encrypt it.
// Requires the command 'unzip' installed
func ZipDecrypt(filePath ...string) error {
	argCount := len(filePath)
	if argCount < 2 {
		return fmt.Errorf("ERROR Must supply file name and key")
	}
	src, key := filePath[0], filePath[1]

	srcDir := filepath.Dir(src)
	srcName := filepath.Base(src)

	fmt.Printf("DEBUG srcDir %s - srcName %s\n", srcDir, srcName)
	cmd := exec.Command("/bin/sh", "-c", "cd "+srcDir+"; /usr/bin/unzip -P '"+key+"' "+srcName)

	_, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Println(cmd.String())
		log.Printf("ERROR ZipDecrypt %v\n", err)
		return fmt.Errorf("ERROR command unzip return error")
	}
	return nil
}

func BcryptHashPassword(password string, cost int) (string, error) {
	//Too slow with cost 14 - Maybe 10 or 6 for normal user, 8 for super user? remember it is 2^cost iterations
	if cost == -1 {
		cost = 10
	}
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	return string(bytes), err
}

func BcryptCheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// Unzip will unzip the 'src' file into the directory 'dest'
// This version is pure go - so no need to have the zip command.
func Unzip(src, dest string) error {
	if dest == "." || dest == "./" {
		dest, _ = os.Getwd()
	}
	r, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer func() {
		if err := r.Close(); err != nil {
			panic(err)
		}
	}()
	os.MkdirAll(dest, 0o777)
	// Closure to address file descriptors issue with all the deferred .Close() methods
	extractAndWriteFile := func(f *zip.File) error {
		rc, err := f.Open()
		if err != nil {
			return err
		}
		defer func() {
			if err := rc.Close(); err != nil {
				panic(err)
			}
		}()
		path := filepath.Join(dest, f.Name)
		// Check for ZipSlip (Directory traversal)
		if !strings.HasPrefix(path, filepath.Clean(dest)+string(os.PathSeparator)) {
			return fmt.Errorf("illegal file path: %s", path)
		}
		if f.FileInfo().IsDir() {
			os.MkdirAll(path, f.Mode())
		} else {
			os.MkdirAll(filepath.Dir(path), f.Mode())
			f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
			if err != nil {
				return err
			}
			defer func() {
				if err := f.Close(); err != nil {
					panic(err)
				}
			}()
			_, err = io.Copy(f, rc)
			if err != nil {
				return err
			}
		}
		return nil
	}
	for _, f := range r.File {
		err := extractAndWriteFile(f)
		if err != nil {
			return err
		}
	}
	return nil
}

func ReadFileToBase64Content(filename string) string {
	f, _ := os.Open(filename)
	reader := bufio.NewReader(f)
	content, _ := io.ReadAll(reader)
	// Encode as base64.
	return base64.StdEncoding.EncodeToString(content)
}

// SendMail sends an email with a text body and multiple attachments over SSL/TLS if requested
func SendMail(from string, to []string, subject, body string, attachmentPaths []string, smtpServerInfo, username, password string, useSSL bool) error {
	_serverInfor := strings.Split(smtpServerInfo, ":")
	smtpServer, smtpPort := _serverInfor[0], Ternary(useSSL, "465", "25")
	if len(_serverInfor) == 2 {
		smtpPort = _serverInfor[1]
	}
	// Create the buffer to build the MIME message
	var emailContent bytes.Buffer

	// Create a multipart message with 'mixed' type (for attachments)
	writer := multipart.NewWriter(&emailContent)

	// Set the headers for the email
	headers := map[string]string{
		"From":    from,
		"To":      strings.Join(to, ", "),
		"Subject": subject,
	}

	// Write headers to the email content
	for key, value := range headers {
		emailContent.WriteString(fmt.Sprintf("%s: %s\r\n", key, value))
	}

	// Add a blank line between headers and the body
	emailContent.WriteString("\r\n")

	// Create the text part of the email (the body)
	textPart, _ := writer.CreatePart(map[string][]string{
		"Content-Type": {"text/plain; charset=UTF-8"},
	})
	textPart.Write([]byte(body))

	// Add the attachments (if any)
	for _, attachmentPath := range attachmentPaths {
		attachmentFile, err := os.Open(attachmentPath)
		if err != nil {
			return fmt.Errorf("could not open attachment: %v", err)
		}
		defer attachmentFile.Close()

		// Get the attachment's filename
		_, filename := filepath.Split(attachmentPath)

		// Add the attachment header (Content-Type, Content-Disposition, etc.)
		attachmentHeader := map[string][]string{
			"Content-Type":              {fmt.Sprintf("application/octet-stream; name=\"%s\"", filename)},
			"Content-Transfer-Encoding": {"base64"},
			"Content-Disposition":       {fmt.Sprintf("attachment; filename=\"%s\"", filename)},
		}

		// Create the attachment part
		attachmentPart, _ := writer.CreatePart(attachmentHeader)

		// Encode the file in base64 and write it to the attachment part
		encoder := base64.NewEncoder(base64.StdEncoding, attachmentPart)
		_, err = io.Copy(encoder, attachmentFile)
		if err != nil {
			return fmt.Errorf("could not encode attachment: %v", err)
		}
		encoder.Close()
	}

	// Close the multipart writer (this adds the final boundary)
	writer.Close()

	// Set up SMTP authentication if username is provided
	var auth smtp.Auth
	if username != "" && password != "" {
		auth = smtp.PlainAuth("", username, password, smtpServer)
	}

	// Dial the SMTP server using SSL/TLS or without SSL depending on the useSSL flag
	var conn net.Conn
	var err error

	if useSSL {
		// SSL/TLS connection (use port 465 for SSL)
		conn, err = tls.Dial("tcp", smtpServer+":"+smtpPort, &tls.Config{
			InsecureSkipVerify: true, // Set to false for production environments
		})
		if err != nil {
			return fmt.Errorf("failed to dial SMTP server over SSL/TLS: %v", err)
		}
	} else {
		// Non-SSL connection (use port 587 for STARTTLS or 25 for no encryption)
		conn, err = net.Dial("tcp", smtpServer+":"+smtpPort)
		if err != nil {
			return fmt.Errorf("failed to dial SMTP server without SSL: %v", err)
		}
	}

	// Create a new SMTP client
	client, err := smtp.NewClient(conn, smtpServer)
	if err != nil {
		return fmt.Errorf("failed to create SMTP client: %v", err)
	}

	// If using STARTTLS, initiate the STARTTLS upgrade
	if !useSSL {
		if err := client.StartTLS(&tls.Config{
			InsecureSkipVerify: true,
		}); err != nil {
			return fmt.Errorf("failed to start TLS: %v", err)
		}
	}

	// Authenticate with the SMTP server if username is provided
	if auth != nil {
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("SMTP authentication failed: %v", err)
		}
	}

	// Set the sender and recipients
	if err := client.Mail(from); err != nil {
		return fmt.Errorf("failed to set sender: %v", err)
	}
	for _, recipient := range to {
		if err := client.Rcpt(recipient); err != nil {
			return fmt.Errorf("failed to set recipient: %v", err)
		}
	}

	// Write the email body to the client
	dataWriter, err := client.Data()
	if err != nil {
		return fmt.Errorf("failed to write email body: %v", err)
	}

	_, err = dataWriter.Write(emailContent.Bytes())
	if err != nil {
		return fmt.Errorf("failed to send email data: %v", err)
	}

	// Close the client session
	err = dataWriter.Close()
	if err != nil {
		return fmt.Errorf("failed to close data writer: %v", err)
	}

	// Quit the session
	client.Quit()

	return nil
}

// FileTouch is similar the unix command 'touch'. If file does not exists, an empty file will be created
func FileTouch(fileName string) error {
	_, err := os.Stat(fileName)
	if os.IsNotExist(err) {
		file, err := os.Create(fileName)
		if err != nil {
			return err
		}
		defer file.Close()
	} else {
		currentTime := time.Now().Local()
		err = os.Chtimes(fileName, currentTime, currentTime)
		if err != nil {
			return err
		}
	}
	return nil
}

// FileExists test if file 'name' exists
func FileExists(name string) (bool, error) {
	_, err := os.Stat(name)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, err
}

// This is short version of FileExists - meant to be use in Ternery like Ternary(FileExistsV2(path) == nil, "something", "somethingelse")
func FileExistsV2(name string) error {
	_, err := os.Stat(name)
	return err
}

// GenRandomString generates a random string with length 'n'
func GenRandomString(n int) string {
	return MakePassword(n)
	// mrand.Seed(time.Now().UnixNano())
	// b := make([]byte, n)
	// for i := range b {
	// 	b[i] = LetterBytes[mrand.Intn(len(LetterBytes))]
	// }
	// return string(b)
}

func RunDSL(dbc *sql.DB, sql string) map[string]interface{} {
	stmt, err := dbc.Prepare(sql)
	if err != nil {
		return map[string]interface{}{"result": nil, "error": err}
	}
	defer stmt.Close()
	result, err := stmt.Exec()
	return map[string]interface{}{"result": result, "error": err}
}

// Run SELECT and return map[string]interface{}{"result": []interface{}, "error": error}
func RunSQL(dbc *sql.DB, sql string) map[string]interface{} {
	var result = make([]interface{}, 0)
	ptn := regexp.MustCompile(`[\s]+(from|FROM)[\s]+([^\s]+)[\s]*`)
	if matches := ptn.FindStringSubmatch(sql); len(matches) == 3 {
		stmt, err := dbc.Prepare(sql)
		if err != nil {
			return map[string]interface{}{"result": nil, "error": err}
		}
		defer stmt.Close()
		rows, err := stmt.Query()
		if err != nil {
			return map[string]interface{}{"result": nil, "error": err}
		}
		defer rows.Close()
		columnNames, err := rows.Columns() // []string{"id", "name"}
		if err != nil {
			return map[string]interface{}{"result": nil, "error": err}
		}
		columns := make([]interface{}, len(columnNames))
		columnTypes, _ := rows.ColumnTypes()
		columnPointers := make([]interface{}, len(columnNames))
		for i := range columns {
			columnPointers[i] = &columns[i]
		}
		for rows.Next() {
			err := rows.Scan(columnPointers...)
			if err != nil {
				return map[string]interface{}{"result": nil, "error": err}
			}
			_temp := make(map[string]interface{})
			for idx, _cName := range columnNames {
				if strings.ToUpper(columnTypes[idx].DatabaseTypeName()) == "TEXT" {
					//avoid auto base64 enc by golang when hitting the []byte type
					//not sure why some TEXT return []uint8 other return as string.
					_data, ok := columns[idx].([]uint8)
					if ok {
						_temp[_cName] = string(_data)
					} else {
						_temp[_cName] = columns[idx]
					}
				} else {
					_temp[_cName] = columns[idx]
				}
			}
			result = append(result, _temp)
		}
	} else {
		return map[string]interface{}{"result": nil, "error": errors.New("ERROR Malformed sql, no table name found")}
	}
	return map[string]interface{}{"result": result, "error": nil}
}

// RemoveDuplicate remove duplicated item in a slice
func RemoveDuplicate[T comparable](slice []T) []T {
	allKeys := make(map[T]bool)
	list := []T{}
	for _, item := range slice {
		if _, value := allKeys[item]; !value {
			allKeys[item] = true
			list = append(list, item)
		}
	}
	return list
}

// LoadConfigIntoEnv load the json/yaml config file 'configFile' and export env var - var name is the key and value
// is the json value
func LoadConfigIntoEnv(configFile string) map[string]interface{} {
	configObj := ParseConfig(configFile)
	for key, val := range configObj {
		if _val, ok := val.(string); ok {
			if err := os.Setenv(key, _val); err != nil {
				panic(fmt.Sprintf("[ERROR] can not set env vars from yaml config file %v\n", err))
			}
		} else {
			panic(fmt.Sprintf("[ERROR] key %s not set properly. It needs to be non empty and string type. Check your config file", key))
		}
	}
	return configObj
}

// ParseConfig loads the json/yaml config file 'configFile' into a map
// json is tried first and then yaml
func ParseConfig(configFile string) map[string]interface{} {
	if configFile == "" {
		log.Fatalf("Config file required. Run with -h for help")
	}
	configDataBytes, err := os.ReadFile(configFile)
	CheckErr(err, "ParseConfig")
	config := JsonByteToMap(configDataBytes)
	if config == nil {
		err = yaml.Unmarshal(configDataBytes, &config)
		CheckErr(err, "ParseConfig yaml.Unmarshal")
	}
	return config
}

// Mimic the Ternary in other languages but only support simple form so nobody can abuse it
func Ternary[T any](expr bool, x, y T) T {
	if expr {
		return x
	} else {
		return y
	}
}

// return strings.TrimSuffix(fileName, filepath.Ext(fileName))
func FileNameWithoutExtension(fileName string) string {
	return fileName[:len(fileName)-len(filepath.Ext(fileName))]
}

// RunSystemCommand run the command 'cmd'. It will use 'bash -c <the-command>' thus requires bash installed
// On windows you need to install bash or mingw64 shell
// If command exec get error it will panic!
func RunSystemCommand(cmd string, verbose bool) (output string) {
	if verbose {
		log.Printf("[INFO] command: %s\n", cmd)
	}
	command := exec.Command("bash", "-c", cmd)

	combinedOutput, err := command.CombinedOutput()
	if err != nil {
		log.Fatalf("[ERROR] error command: '%s' - %v\n    %s\n", cmd, err, combinedOutput)
	}
	output = fmt.Sprintf("%s", command.Stdout)
	output = strings.TrimSuffix(output, "\n")
	return
}

// RunSystemCommandV2 run the command 'cmd'. It will use 'bash -c <the-command>' thus requires bash installed
// On windows you need to install bash or mingw64 shell
// The only differrence with RunSystemCommand is that it returns an error if error happened and it wont panic
func RunSystemCommandV2(cmd string, verbose bool) (output string, err error) {
	command := exec.Command("bash", "-c", cmd)
	return RunSystemCommandV3(command, verbose)
}

// RunSystemCommandV3. Unlike the other two, this one you craft the exec.Cmd object and pass it to this function
// This allows you to customize the exec.Cmd object before calling this function, eg, passing more env vars into it
// like command.Env = append(os.Environ(), "MYVAR=MYVAL"). You might not need bash to run for example but run directly
func RunSystemCommandV3(command *exec.Cmd, verbose bool) (output string, err error) {
	if verbose {
		log.Printf("[INFO] command: %s\n", MaskCredential(command.String()))
	}
	combinedOutput, err1 := command.CombinedOutput()
	if err1 != nil {
		if verbose {
			return fmt.Sprintf("[ERROR] error command: '%s' - %s\n    %s\n", MaskCredential(command.String()), MaskCredential(err1.Error()), MaskCredential(string(combinedOutput))), err1
		} else {
			return "[ERROR] turn on verbose to display full", err1
		}
	}
	output = fmt.Sprintf("%s", command.Stdout)
	output = strings.TrimSuffix(output, "\n")
	return output, nil
}

func Getenv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func JsonDump(obj interface{}, indent string) string {
	msgByte := JsonDumpByte(obj, indent)
	return string(msgByte)
}

func JsonDumpByte(obj interface{}, indent string) []byte {
	if indent == "" {
		indent = "    "
	}
	msgByte, err := json.MarshalIndent(obj, "", indent)
	if CheckErrNonFatal(err, "JsonDump") == nil {
		return msgByte
	}
	return []byte("")
}

// Given a duration string return a tuple of start time, end time satisfy the duration.
// If duration string is dd/mm/yyyy hh:mm:ss - dd/mm/yyyy hh:mm:ss it simply return two time object.
// If duration is like 15m then endtime is now, start time is 15 minutes ago. This applies for all case if input is not parsable
func ParseTimeRange(durationStr, tz string) (time.Time, time.Time) {
	var start, end time.Time
	if tz == "" {
		tz, _ = time.Now().Zone()
	}
	timerangePtn := regexp.MustCompile(`([\d]{2,2}/[\d]{2,2}/[\d]{4,4} [\d]{2,2}:[\d]{2,2}:[\d]{2,2}) - ([\d]{2,2}/[\d]{2,2}/[\d]{4,4} [\d]{2,2}:[\d]{2,2}:[\d]{2,2})`)
	dur, e := time.ParseDuration(durationStr)
	if e != nil {
		log.Printf("[ERROR] can not parse duration string using time.ParseDuration for %s - %v. Will try next\n", durationStr, e)
		m := timerangePtn.FindStringSubmatch(durationStr)
		if len(m) != 3 {
			log.Printf("[ERROR] Can not parse duration. Set default to 15m ago - %v", e)
			dur, _ = time.ParseDuration("15m")
		} else {
			start, _ = time.Parse(AUTimeLayout, m[1]+" "+tz)
			end, _ = time.Parse(AUTimeLayout, m[2]+" "+tz)
		}
	}
	end = time.Now()
	start = end.Add(-1 * dur)
	// log.Printf("Time range: %s - %s\n",start.Format(AUTimeLayout), end.Format(AUTimeLayout))
	return start, end
}

func Sleep(duration string) {
	d, err := time.ParseDuration(duration)
	CheckErr(err, "ParseDuration")
	time.Sleep(d)
}

func CheckErr(err error, location string) {
	if err != nil {
		log.Fatalf("[ERROR] at %s - %v\n", location, err)
	}
}

func CheckErrNonFatal(err error, location string) error {
	if err != nil {
		msg := fmt.Sprintf("[ERROR] at %s - %v. IGNORED\n", location, err)
		println(msg)
		return fmt.Errorf(msg)
	}
	return nil
}

func CheckNonErrIfMatch(err error, ptn, location string) error {
	if err != nil {
		if strings.Contains(err.Error(), ptn) {
			return fmt.Errorf("[ERROR] at %s - %s", location, err.Error())
		} else {
			log.Fatalf("[ERROR] at %s - %v\n", location, err)
		}
	}
	return nil
}

func Assert(cond bool, msg string, fatal bool) bool {
	if cond {
		log.Printf("Assert Passed - %s\n", msg)
	} else {
		if fatal {
			log.Fatalf("[ERROR] Assert FAILED - %s\n", msg)
		} else {
			log.Printf("[ERROR] Assert FAILED - %s\n", msg)
		}
	}
	return cond
}

// Make a HTTP request to url and get data. Emulate the curl command. Take the env var CURL_DEBUG - set to 'yes' if u need
// more debugging. CA_CERT_FILE, SSL_KEY_FILE, SSL_CERT_FILE correspondingly if required
// To ignore cert check set INSECURE_SKIP_VERIFY to yes
// data set it to empty string if you do not need to send any data.
// savefilename if you do not want to save to a file, set it to empty string
// Same as header array it is a list of string with : as separator. Eg. []string{"Authorization: Bearer <myToken>"}
func Curl(method, url, data, savefilename string, headers []string) (string, error) {
	CURL_DEBUG := Getenv("CURL_DEBUG", "no")
	ca_cert_file := Getenv("CA_CERT_FILE", "")
	ssl_key_file := Getenv("SSL_KEY_FILE", "")
	ssl_cert_file := Getenv("SSL_CERT_FILE", "")
	InsecureSkipVerify := Ternary(Getenv("INSECURE_SKIP_VERIFY", "no") == "yes", true, false)

	var cert *tls.Certificate = nil
	var err error
	if ssl_cert_file != "" && ssl_key_file != "" {
		if CURL_DEBUG == "yes" {
			log.Printf("Load ssl cert %s and key %s\n", ssl_cert_file, ssl_key_file)
		}
		*cert, err = tls.LoadX509KeyPair(ssl_cert_file, ssl_key_file)
		if err != nil {
			log.Printf("[ERROR] can not LoadX509KeyPair\n")
			return "", err
		}
	}
	var caCertPool *x509.CertPool = nil
	if ca_cert_file != "" {
		if CURL_DEBUG == "yes" {
			log.Printf("Load CA cert %s\n", ca_cert_file)
		}
		caCert, err := os.ReadFile(ca_cert_file)
		if err != nil {
			log.Println("[ERROR] Load CA cert")
			return "", err
		}
		caCertPool = x509.NewCertPool()
		if ok := caCertPool.AppendCertsFromPEM(caCert); !ok {
			log.Printf("[ERROR] can not AppendCertsFromPEM\n")
		}
	}
	var tlsConfig *tls.Config = nil

	if caCertPool != nil || cert != nil || InsecureSkipVerify {
		if CURL_DEBUG == "yes" {
			log.Printf("[DEBUG] going to create tlsConfig with caCertPool '%v' - cert '%v'\n", caCertPool, cert)
		}
		tlsConfig = &tls.Config{InsecureSkipVerify: InsecureSkipVerify}

		if cert != nil {
			tlsConfig.Certificates = []tls.Certificate{*cert}
		}
		if caCertPool != nil {
			tlsConfig.RootCAs = caCertPool
		}
	}

	var client *http.Client = nil

	if tlsConfig != nil {
		if CURL_DEBUG == "yes" {
			log.Printf("[DEBUG] going to create transport with tlsConfig '%v'\n", tlsConfig)
		}
		transport := &http.Transport{TLSClientConfig: tlsConfig}
		client = &http.Client{Transport: transport}
	} else {
		if CURL_DEBUG == "yes" {
			log.Println("[DEBUG] no tlsconfig is set, use default http client")
		}
		client = &http.Client{}
	}

	if CURL_DEBUG == "yes" {
		log.Printf("[DEBUG] http client - %v\n", client)
		log.Printf("[DEBUG] tls config - %v\n", tlsConfig)
		log.Printf("[DEBUG] ca_cert_file '%v' - ssl_key_file '%v' ssl_cert_file '%v' insecureSkipVerify %v\n", ca_cert_file, ssl_key_file, ssl_cert_file, InsecureSkipVerify)
	}

	req, err := http.NewRequest(method, url, bytes.NewBuffer([]byte(data)))
	if err != nil {
		return "", err
	}
	for _, line := range headers {
		_tmp := strings.Split(line, ":")
		req.Header.Set(_tmp[0], strings.TrimSpace(_tmp[1]))
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if savefilename == "" {
		content, err := io.ReadAll(resp.Body)
		if err != nil {
			return "", err
		}
		return string(content), nil
	} else {
		outfile, err := os.Create(savefilename)
		if err != nil {
			return "", err
		}
		defer outfile.Close()
		_, err = io.Copy(outfile, resp.Body)
		if err != nil {
			return "", err
		}
		return "OK save to " + savefilename, nil
	}
}

// MakeRequest make a http request with method (POST or GET etc...). It support sessions - if you have existing session stored in cookie jar then pass it to
// the `jar` param otherwise a new cookie ja session will be created.
// config has these keys:
// - timeout - set the time out of time int. Default is 600 secs
// - url - the URL that the request will be sent to
// - token - string - the Authorization token if required. It will make the header 'Authorization' using the token
// - headers - a map[string]string to pass any arbitrary reuqets headers Key : Value
// Return value is the response. If it is a json of type list then it will be put into the key "results"
// This is used to make API REST requests and expect response as json. To download or do more general things, use the function
// Curl above instead
func MakeRequest(method string, config map[string]interface{}, data []byte, jar *cookiejar.Jar) map[string]interface{} {
	if jar == nil {
		jar, _ = cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	}
	_timeout, ok := config["timeout"].(int64)
	if !ok {
		_timeout = 600
	}
	client := http.Client{
		Jar:     jar,
		Timeout: time.Duration(_timeout) * time.Second,
	}
	_url, ok := config["url"].(string)
	if !ok {
		log.Printf("[ERROR] config[\"url\"] value required")
		return map[string]interface{}{}
	}
	req, err := http.NewRequest(method, _url, bytes.NewBuffer(data))
	CheckErrNonFatal(err, "MakeRequest req")
	_token, ok := config["token"].(string)
	if ok {
		req.Header.Set("Authorization", _token)
	}
	headers, ok := config["headers"].(map[string]string)
	if ok {
		for k, v := range headers {
			req.Header.Set(k, v)
		}
	}
	resp, err := client.Do(req)
	CheckErrNonFatal(err, "MakeRequest client.Do")
	defer resp.Body.Close()
	content, err := io.ReadAll(resp.Body)
	CheckErrNonFatal(err, "MakeRequest Readall")
	if content[0] == []byte("[")[0] {
		var m []interface{}
		if CheckErrNonFatal(json.Unmarshal(content, &m), "MakeRequest Unmarshall") != nil {
			log.Printf("Api return %v\nreq: %v\n", m, req)
			return map[string]interface{}{}
		} else {
			return map[string]interface{}{
				"results": m,
			}
		}
	} else {
		m := map[string]interface{}{}
		if CheckErrNonFatal(json.Unmarshal(content, &m), "MakeRequest Unmarshall") != nil {
			log.Printf("Api return %v\nreq: %v\n", m, req)
			return map[string]interface{}{}
		} else {
			return m
		}
	}
}

// Prepare a form that you will submit to that URL.
// client if it is nil then new http client will be used
// url is the url the POST request to
// values is a map which key is the postform field name. The value of the map should be any io.Reader to read data from
// like *os.File to post attachment etc..
// mimetype if set which has the key is the file name in the values above, and the value is the mime type of that file
// headers is extra header in the format key/value pair. note the header 'Content-Type' should be automatically added
// Note:
// This is not working for report portal (RP) basically golang somehow send it using : Content type 'application/octet-stream' (or the server complain about that not supported). There are two parts each of them has different content type and it seems golang implementation does not fully support it? (the jsonPaths must be application-json).
// For whatever it is, even the header printed out correct - server complain. Curl work though so we will use curl for now
// I think golang behaviour is correct it should be 'application/octet-stream' for the file part, but the RP java server does not behave.
// So we add a manual set header map in for this case
func Upload(client *http.Client, url string, values map[string]io.Reader, mimetype map[string]string, headers map[string]string) (err error) {
	if client == nil {
		client = &http.Client{}
	}
	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	for key, r := range values {
		var fw io.Writer
		if x, ok := r.(io.Closer); ok {
			defer x.Close()
		}
		if x, ok := r.(*os.File); ok {
			itemMimeType, ok := mimetype[x.Name()]
			if ok {
				partHeader := textproto.MIMEHeader{}
				partHeader.Set("Content-Disposition", fmt.Sprintf(`form-data; name="%s"; filename="%s"`, key, x.Name()))
				partHeader.Set("Content-Type", itemMimeType)
				fw, err = w.CreatePart(partHeader)
				if CheckErrNonFatal(err, "Upload/CreatePart") != nil {
					return err
				}
			} else {
				if fw, err = w.CreateFormFile(key, x.Name()); err != nil {
					return err
				}
			}
		} else {
			// Add other fields
			if fw, err = w.CreateFormField(key); err != nil {
				return err
			}
		}
		if _, err = io.Copy(fw, r); err != nil {
			return err
		}
	}
	// Don't forget to close the multipart writer.
	// If you don't close it, your request will be missing the terminating boundary.
	w.Close()

	// Now that you have a form, you can submit it to your handler.
	req, err := http.NewRequest("POST", url, &b)
	if err != nil {
		return err
	}
	// Don't forget to set the content type, this will contain the boundary.
	req.Header.Set("Content-Type", w.FormDataContentType())
	// req.Header.Set("Content-Type", "multipart/form-data")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	// Submit the request
	// log.Printf("[DEBUG] REQ: %v\n", req)
	rsp, err := client.Do(req)
	if CheckErrNonFatal(err, fmt.Sprintf("[ERROR] AttachFileToRPItem Request failed with response: %v - code %d\n", rsp, rsp.StatusCode)) != nil {
		return err
	}
	// Check the response
	if rsp.StatusCode != http.StatusCreated {
		log.Printf("[ERROR] AttachFileToRPItem Request failed with response: %v - code %d\n", rsp, rsp.StatusCode)
		err = fmt.Errorf("bad status: %s", rsp.Status)
		return err
	}
	return nil
}

// Add or delete attrbs set in a to b. action can be 'add'; if it is empty it will do a delete.
// a and b is a list of map of items having two fields, key and value.
// If key does not exists in b and action is add - it will add it to b
// If key is matched found and
// If key is not nil and b will be updated or delete per action
// If key is nil and value matched and action is not add - the item will be removed
func MergeAttributes(a, b []interface{}, action string) []interface{} {
	if len(a) == 0 {
		return b
	}
STARTLOOP:
	for _, _a := range a {
		_a1 := _a.(map[string]interface{})
		found := false
		for idxb, _b := range b {
			_b1 := _b.(map[string]interface{})
			if _a1["key"] == _b1["key"] {
				if _a1["key"] != nil {
					if action == "add" {
						b[idxb].(map[string]interface{})["value"] = _a1["value"]
						found = true
						continue STARTLOOP
					} else {
						b = RemoveItemByIndex(b, idxb)
						found = true
						continue
					}
				} else { //both key is nil
					if _a1["value"] == _b1["value"] {
						found = true
						if action == "add" {
							continue
						} else {
							b = RemoveItemByIndex(b, idxb)
						}
					}
				}
			}
		}
		//if reach here and not found we add new one
		if !found && action == "add" {
			b = append(b, _a)
		}
	}
	return b
}

func MustOpenFile(f string) *os.File {
	r, err := os.Open(f)
	CheckErr(err, fmt.Sprintf("MustOpenFile %s", f))
	return r
}

// RemoveItem This func is depricated Use RemoveItemByIndex. Remove an item of the index i in a slice
func RemoveItem(s []interface{}, i int) []interface{} {
	s[i] = s[len(s)-1]
	// We do not need to put s[i] at the end, as it will be discarded anyway
	return s[:len(s)-1]
}

// RemoveItemByIndex removes an item from a slice of any type. Using the index of the item.
func RemoveItemByIndex[T comparable](s []T, i int) []T {
	s[i] = s[len(s)-1]
	return s[:len(s)-1]
}

// RemoveItemByVal removes an item from a slice of any type
func RemoveItemByVal[T comparable](slice []T, item T) []T {
	for i, v := range slice {
		if v == item {
			return append(slice[:i], slice[i+1:]...)
		}
	}
	return slice
}

type AppConfigProperties map[string]string

// ReadPropertiesString read from a string with format like 'key=value' and return AppConfigProperties
// which is a map[string]string
func ReadPropertiesString(inputString string) (AppConfigProperties, error) {
	_tempLst := strings.Split(inputString, "\n")
	output := make(map[string]string)
	for _, line := range _tempLst {
		_tempLst1 := strings.Split(line, "=")
		if (len(_tempLst1) == 2) && (_tempLst1[0] != "") {
			output[_tempLst1[0]] = _tempLst1[1]
		}
	}
	return output, nil
}

// ReadPropertiesFile read from a file with content format like 'key=value' and return AppConfigProperties
// which is a map[string]string
func ReadPropertiesFile(filename string) (AppConfigProperties, error) {
	config := AppConfigProperties{}

	if len(filename) == 0 {
		return config, nil
	}
	file, err := os.Open(filename)
	if err != nil {
		log.Printf("ReadPropertiesFile %v\n", err)
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if equal := strings.Index(line, "="); equal >= 0 {
			if key := strings.TrimSpace(line[:equal]); len(key) > 0 {
				value := ""
				if len(line) > equal {
					value = strings.TrimSpace(line[equal+1:])
				}
				config[key] = value
			}
		}
	}
	if err := scanner.Err(); err != nil {
		log.Printf("ReadPropertiesFile %v\n", err)
		return nil, err
	}
	return config, nil
}

// MapLookup search a key in a map and return the value if found, otherwise return the default_val
func MapLookup(m map[string]any, key string, default_val any) any {
	if v, ok := m[key]; ok {
		return v
	} else {
		return default_val
	}
}

// Crypto utils
func GenSelfSignedKey(keyfilename string) {
	// priv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"ABB PGES Co"},
			CommonName:   "oidc-test",
			Country:      []string{"AU"},
			Locality:     []string{"Brisbane"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 24 * 180),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey(priv), priv)
	if err != nil {
		log.Fatalf("Failed to create certificate: %s", err)
	}
	out := &bytes.Buffer{}
	pem.Encode(out, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	// fmt.Println(out.String())
	if err := os.WriteFile(fmt.Sprintf("%s.crt", keyfilename), out.Bytes(), 0640); err != nil {
		log.Fatalf("can not write public key %v\n", err)
	}

	out.Reset()
	pem.Encode(out, pemBlockForKey(priv))
	if err := os.WriteFile(fmt.Sprintf("%s.key", keyfilename), out.Bytes(), 0600); err != nil {
		log.Fatalf("can not write private key %v\n", err)
	}
	// fmt.Println(out.String())
}

func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}
func pemBlockForKey(priv interface{}) *pem.Block {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to marshal ECDSA private key: %v", err)
			os.Exit(2)
		}
		return &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
	default:
		return nil
	}
}

// Pass an interface, return same interface if they are map of string to interface or list of string as key
func ValidateInterfaceWithStringKeys(val interface{}) (interface{}, error) {
	switch val := val.(type) {
	case map[interface{}]interface{}:
		m := make(map[string]interface{})
		for k, v := range val {
			k, ok := k.(string)
			if !ok {
				return nil, fmt.Errorf("found non-string key '%v'", k)
			}
			m[k] = v
		}
		return m, nil
	case []interface{}:
		var err error
		var l = make([]interface{}, len(val))
		for i, v := range l {
			l[i], err = ValidateInterfaceWithStringKeys(v)
			if err != nil {
				return nil, err
			}
		}
		return l, nil
	default:
		return val, nil
	}
}

// Must wraps two values pair with second one is an error, check if error is nil then return the first, otherwise panic with error message
func Must[T any](res T, err error) T {
	if err != nil {
		anyT, msg := any(res), ""
		if o, ok := anyT.(string); ok {
			msg = o + "- error: " + err.Error()
		} else {
			msg = err.Error()
		}
		panic(msg)
	}
	return res
}

// Common usefull go text template funcs. Not thread safe, you should modify it once before spawning all others if you need to modify it
func tmpl_inc(i int) int {
	return i + 1
}
func tmpl_add(x, y int) int {
	return x + y
}
func tmpl_lower(word string) string {
	return cases.Lower(language.English, cases.NoLower).String(word)
}
func tmpl_title(word string) string {
	return cases.Title(language.English, cases.NoLower).String(word)
}
func tmpl_upper(word string) string {
	return cases.Upper(language.English, cases.NoLower).String(word)
}
func tmpl_time_fmt(timelayout string, timeticks int64) string {
	return NsToTime(timeticks).Format(timelayout)
}
func tmpl_now(timelayout string) string {
	return time.Now().Format(timelayout)
}
func tmpl_join(sep string, inlist []string) string { return strings.Join(inlist, sep) }

func tmpl_truncatechars(length int, in string) string {
	return string(ChunkString(in, length)[0])
}
func tmpl_cycle(idx int, vals ...string) string {
	_idx := idx % len(vals)
	return string(vals[_idx])
}
func tmpl_replace(old, new, data string) string {
	o := strings.ReplaceAll(data, old, new)
	return o
}
func tmpl_contains(subStr, data string) bool {
	return strings.Contains(data, subStr)
}
func tmpl_int_range(start, end int) []int {
	n := end - start
	result := make([]int, n)
	for i := 0; i < n; i++ {
		result[i] = start + i
	}
	return result
}
func tmpl_basename(file_path string) string {
	return filepath.Base(file_path)
}
func tmpl_dirname(file_path string) string {
	return filepath.Dir(file_path)
}
func tmpl_toyaml(v interface{}) string {
	data, err := yaml.Marshal(v)
	if err != nil {
		return ""
	}
	return strings.TrimSuffix(string(data), "\n")
}

// Stole it from here https://github.com/helm/helm/blob/main/pkg/engine/funcs.go
func tmpl_to_niceyaml(v interface{}) string {
	var data bytes.Buffer
	encoder := yaml.NewEncoder(&data)
	encoder.SetIndent(2)
	err := encoder.Encode(v)

	if err != nil {
		// Swallow errors inside of a template.
		return ""
	}
	return strings.TrimSuffix(data.String(), "\n")
}

// stole from here https://github.com/Masterminds/sprig. If more than these we probably just use them :)
func tmpl_tojson(v interface{}) string {
	data, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(data)
}
func indent(spaces int, v string) string {
	pad := strings.Repeat(" ", spaces)
	return pad + strings.Replace(v, "\n", "\n"+pad, -1)
}
func FormatSizeInByte(size int64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
	)

	if size >= GB {
		return fmt.Sprintf("%.2f GB", float64(size)/float64(GB))
	} else if size >= MB {
		return fmt.Sprintf("%.2f MB", float64(size)/float64(MB))
	} else if size >= KB {
		return fmt.Sprintf("%.2f KB", float64(size)/float64(KB))
	}
	return fmt.Sprintf("%d bytes", size)
}

// Common func for go text template
var GoTextTemplateFuncMap = template.FuncMap{
	"format_size":   FormatSizeInByte,
	"inc":           tmpl_inc,
	"add":           tmpl_add,
	"title":         tmpl_title,
	"lower":         tmpl_lower,
	"upper":         tmpl_upper,
	"time_fmt":      tmpl_time_fmt,
	"now":           tmpl_now,
	"join":          tmpl_join,
	"truncatechars": tmpl_truncatechars,
	"cycle":         tmpl_cycle,
	"replace":       tmpl_replace,
	"contains":      tmpl_contains,
	"int_range":     tmpl_int_range,
	"basename":      tmpl_basename,
	"dirname":       tmpl_dirname,
	"to_yaml":       tmpl_toyaml,
	"to_nice_yaml":  tmpl_to_niceyaml,
	"to_json":       tmpl_tojson,
	"indent":        indent,
	"nindent": func(spaces int, v string) string {
		return "\n" + indent(spaces, v)
	},
	"regex_search": func(regex string, s string) bool {
		match, _ := regexp.MatchString(regex, s)
		return match
	},
	"regex_replace": func(regex string, repl string, s string) string {
		r := regexp.MustCompile(regex)
		return r.ReplaceAllString(s, repl)
	},
}

// Common usefull go html template funcs
var GoTemplateFuncMap = htmltemplate.FuncMap{
	// The name "inc" is what the function will be called in the template text.
	"format_size": FormatSizeInByte,
	"inc":         tmpl_inc,
	"add":         tmpl_add,
	"title":       tmpl_title,
	"lower":       tmpl_lower,
	"upper":       tmpl_upper,
	"time_fmt":    tmpl_time_fmt,
	"now":         tmpl_now,
	"raw_html": func(html string) htmltemplate.HTML {
		return htmltemplate.HTML(html)
	},
	"unsafe_raw_html": func(html string) htmltemplate.HTML {
		return htmltemplate.HTML(html)
	},
	"if_ie": func() htmltemplate.HTML {
		return htmltemplate.HTML("<!--[if IE]>")
	},
	"end_if_ie": func() htmltemplate.HTML {
		return htmltemplate.HTML("<![endif]-->")
	},
	"join": tmpl_join,
	"truncatechars": func(length int, in string) htmltemplate.HTML {
		return htmltemplate.HTML(ChunkString(in, length)[0])
	},
	"cycle": func(idx int, vals ...string) htmltemplate.HTML {
		_idx := idx % len(vals)
		return htmltemplate.HTML(vals[_idx])
	},
	"replace": func(data, old, new string) htmltemplate.HTML {
		o := strings.ReplaceAll(data, old, new)
		return htmltemplate.HTML(o)
	},
	"contains": func(data, subStr string) bool {
		return strings.Contains(data, subStr)
	},
	"int_range": tmpl_int_range,
	"basename":  tmpl_basename,
	"dirname":   tmpl_dirname,
	"regex_search": func(regex string, s string) bool {
		match, _ := regexp.MatchString(regex, s)
		return match
	},
	"regex_replace": func(regex string, repl string, s string) string {
		r := regexp.MustCompile(regex)
		return r.ReplaceAllString(s, repl)
	},
}

// This func use text/template to avoid un-expected html escaping.
func GoTemplateString(srcString string, data any) string {
	firstLine, remain := SplitFirstLine(srcString)
	found, variable_start, variable_end := parseGoTemplateConfig(firstLine, `#gotmpl:`)
	if found {
		srcString = remain
	}
	t1 := template.Must(template.New("").Delims(variable_start, variable_end).Funcs(GoTextTemplateFuncMap).Parse(srcString))
	var buff bytes.Buffer
	CheckErr(t1.Execute(&buff, data), "GoTemplateString Execute")
	return buff.String()
}

func parseGoTemplateConfig(configLine, prefix string) (found bool, variable_start, variable_end string) { // intentionaly not checking prefix for this case
	variable_start, variable_end, found = `{{`, `}}`, false
	for _, _token := range strings.Split(strings.TrimPrefix(configLine, prefix), ",") {
		_token0 := strings.TrimSpace(_token)
		_data := strings.Split(_token0, ":")
		switch _data[0] {
		case "variable_start_string":
			found = true
			variable_start = strings.Trim(strings.Trim(_data[1], `'`), `"`)
		case "variable_end_string":
			found = true
			variable_end = strings.Trim(strings.Trim(_data[1], `'`), `"`)
		}
	}
	return
}

// This func use text/template to avoid un-expected html escaping.
func GoTemplateFile(src, dest string, data map[string]interface{}, fileMode os.FileMode) {
	goTemplateDelimeter := []string{`{{`, `}}`}
	if firstLine, restFile, matchedPrefix, err := ReadFirstLineWithPrefix(src, []string{`#gotmpl:`, `//gotmpl:`}); err == nil {
		// Example first line is (similar to jinja2 ansible first line format so we do not need to remember new thing again)
		//gotmpl:variable_start_string:'{$', variable_end_string:'$}'
		_, goTemplateDelimeter[0], goTemplateDelimeter[1] = parseGoTemplateConfig(firstLine, matchedPrefix)

		if restFile != "" {
			src = restFile // We now read the source of template using this file which has the first line removed
			defer os.RemoveAll(restFile)
		}
	}
	if fileMode == 0 {
		fileMode = 0o777
	}
	srcByte := Must(os.ReadFile(src))
	t1 := template.Must(template.New("").Delims(goTemplateDelimeter[0], goTemplateDelimeter[1]).Funcs(GoTextTemplateFuncMap).Parse(string(srcByte)))
	destFile := Must(os.Create(dest))
	CheckErr(destFile.Chmod(fileMode), fmt.Sprintf("[ERROR] GoTemplateFile can not chmod %d for file %s\n", fileMode, dest))
	defer destFile.Close()
	CheckErr(t1.Execute(destFile, data), "[ERROR] GoTemplateFile Can not template "+src+" => "+dest)
}

// StructInfo hold information about a struct
type StructInfo struct {
	// Name of the struct
	Name string
	// List of all struct field names
	FieldName []string
	// map lookup by field name => field type
	FieldType map[string]string
	// map lookup by field name => field value
	FieldValue map[string]any
	// map lookup by field name => the capture of struct tags. When calling ReflectStruct you give it the tagPtn
	// here is what you get by using FindAllStringSubmatch of that regex ptn.
	TagCapture map[string][][]string
}

// Give it a struct and a tag pattern to capture the tag content - return a StructInfo obj
func ReflectStruct(astruct any, tagPtn string) StructInfo {
	if tagPtn == "" {
		tagPtn = `db:"([^"]+)"`
	}
	o := StructInfo{}
	tagExtractPtn := regexp.MustCompile(tagPtn)

	rf := reflect.TypeOf(astruct)
	o.Name = rf.Name()
	if rf.Kind().String() != "struct" {
		panic("I need a struct")
	}
	rValue := reflect.ValueOf(astruct)
	o.FieldName = []string{}
	o.FieldType = map[string]string{}
	o.FieldValue = map[string]any{}
	o.TagCapture = map[string][][]string{}
	for i := 0; i < rf.NumField(); i++ {
		f := rf.Field(i)
		o.FieldName = append(o.FieldName, f.Name)
		fieldValue := rValue.Field(i)
		o.FieldType[f.Name] = fieldValue.Type().String()
		o.TagCapture[f.Name] = [][]string{}
		switch fieldValue.Type().String() {
		case "string":
			o.FieldValue[f.Name] = fieldValue.String()
		case "int64", "int", "int32":
			o.FieldValue[f.Name] = fieldValue.Int()
		case "float64", "float32":
			o.FieldValue[f.Name] = fieldValue.Float()
		default:
			// fmt.Println("[INFO] u.ReflectStruct - Unsupported field type " + fieldValue.Type().String())
			o.FieldValue[f.Name] = fieldValue
		}
		if ext := tagExtractPtn.FindAllStringSubmatch(string(f.Tag), -1); ext != nil {
			o.TagCapture[f.Name] = append(o.TagCapture[f.Name], ext...)
		}
	}
	return o
}

// Take a slice and a function return new slice with the value is the result of the function called for each item
// Similar to list walk in python
func SliceMap[T, V any](ts []T, fn func(T) *V) []V {
	result := []V{}
	for _, t := range ts {
		_v := fn(t)
		if _v != nil {
			result = append(result, *_v)
		}
	}
	return result
}

// Similar to the python dict.keys()
func MapKeysToSlice(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m)) // Preallocate slice with the map's size
	for key := range m {
		keys = append(keys, key)
	}
	return keys
}

// Function to convert interface{} => list string
func ConvertListIfaceToListStr(in interface{}) []string {
	o := []string{}
	for _, v := range in.([]interface{}) {
		o = append(o, v.(string))
	}
	return o
}

func InterfaceToStringList(in []interface{}) []string {
	o := []string{}
	for _, v := range in {
		o = append(o, v.(string))
	}
	return o
}

func InterfaceToStringMap(in map[string]interface{}) map[string]string {
	o := map[string]string{}
	for k, v := range in {
		o[k] = v.(string)
	}
	return o
}

// SliceToMap convert a slice of any comparable into a map which can set the value later on
func SliceToMap[T comparable](slice []T) map[T]interface{} {
	set := make(map[T]interface{})
	for _, element := range slice {
		set[element] = nil
	}
	return set
}

func AssertInt64ValueForMap(input map[string]interface{}) map[string]interface{} {
	for k, v := range input {
		if v, ok := v.(float64); ok {
			input[k] = int64(v)
		}
	}
	return input
}

// JsonByteToMap take a json as []bytes and decode it into a map[string]any.
func JsonByteToMap(jsonByte []byte) map[string]any {
	result := make(map[string]interface{})
	err := json.Unmarshal(jsonByte, &result)
	if err != nil {
		return nil
	}
	return result
}

// JsonToMap take a json string and decode it into a map[string]interface{}.
// Note that the value if numeric will be cast it to int64. If it is not good for your case, use the func
// JsonByteToMap which does not manipulate this data
func JsonToMap(jsonStr string) map[string]interface{} {
	result := JsonByteToMap([]byte(jsonStr))
	if result == nil {
		return nil
	}
	return AssertInt64ValueForMap(result)
}

// Take a struct and convert into a map[string]any - the key of the map is the struct field name, and the value is the struct field value.
// This is useful to pass it to the gop template to render the struct value
func ConvertStruct2Map[T any](t T) ([]string, map[string]any) {
	sInfo := ReflectStruct(t, "")
	out := map[string]any{}
	for _, f := range sInfo.FieldName {
		out[f] = sInfo.FieldValue[f]
	}
	return sInfo.FieldName, out
}

func ParseJsonReqBodyToMap(r *http.Request) map[string]interface{} {
	switch r.Method {
	case "POST", "PUT", "DELETE":
		jsonBytes := bytes.Buffer{}
		if _, err := io.Copy(&jsonBytes, r.Body); err != nil {
			fmt.Fprintf(os.Stderr, "[ERROR] ParseJSONToMap loading request body - %s\n", err.Error())
			return nil
		}
		defer r.Body.Close()
		return JsonByteToMap(jsonBytes.Bytes())
	default:
		fmt.Fprintf(os.Stderr, "[ERROR] ParseJSONToMap Do not call me with this method - %s\n", r.Method)
		return nil
	}
}

// ParseJSON parses the raw JSON body from an HTTP request into the specified struct.
func ParseJsonReqBodyToStruct[T any](r *http.Request) *T {
	switch r.Method {
	case "POST", "PUT", "DELETE":
		decoder := json.NewDecoder(r.Body)
		defer r.Body.Close()
		var data T
		if err := decoder.Decode(&data); err != nil {
			fmt.Fprintf(os.Stderr, "[ERROR] parsing JSON - %s\n", err.Error())
			return nil
		}
		return &data
	default:
		fmt.Fprintf(os.Stderr, "[ERROR] ParseJSON Do not call me with this method - %s\n", r.Method)
		return nil
	}
}

// Check if key of type T exists in a map[T]any
func ItemExists[T comparable](item T, set map[T]any) bool {
	_, exists := set[item]
	return exists
}

// ReplaceAllFuncN extends regexp.Regexp to support count of replacements for []byte
func ReplaceAllFuncN(re *regexp.Regexp, src []byte, repl func([]int, [][]byte) []byte, n int) ([]byte, int) {
	if n == 0 {
		return src, 0
	}

	matches := re.FindAllSubmatchIndex(src, n)
	if matches == nil {
		return src, 0
	}

	var result bytes.Buffer
	lastIndex := 0
	replacementCount := 0
	for _, match := range matches {
		result.Write(src[lastIndex:match[0]])
		submatches := make([][]byte, (len(match) / 2))
		for i := 0; i < len(match); i += 2 {
			if match[i] >= 0 && match[i+1] >= 0 {
				submatches[i/2] = src[match[i]:match[i+1]]
			} else {
				submatches[i/2] = nil
			}
		}
		result.Write(repl(match, submatches))
		lastIndex = match[1]
		replacementCount++
	}
	result.Write(src[lastIndex:])

	return result.Bytes(), replacementCount
}

// Quickly replace. Normally if you want to re-use the regex ptn then better compile the pattern first and used the
// standard lib regex replace func. This only save u some small typing.
// the 'repl' can contain capture using $1 or $2 for first group etc..
func ReplacePattern(input []byte, pattern string, repl string, count int) ([]byte, int) {
	re := regexp.MustCompile(pattern)
	replaceFunc := func(matchIndex []int, submatches [][]byte) []byte {
		expandedRepl := []byte(repl)
		for i, submatch := range submatches {
			if submatch != nil {
				placeholder := fmt.Sprintf("$%d", i)
				expandedRepl = bytes.Replace(expandedRepl, []byte(placeholder), submatch, -1)
			}
		}
		return expandedRepl
	}
	return ReplaceAllFuncN(re, input, replaceFunc, count)
}

// Same as ReplacePattern but do regex search and replace in a file
func SearchReplaceFile(filename, ptn, repl string, count int, backup bool) int {
	finfo := Must(os.Stat(filename))
	fmode := finfo.Mode()
	if !(fmode.IsRegular()) {
		panic("CopyFile: non-regular destination file")
	}
	data := Must(os.ReadFile(filename))
	if backup {
		os.WriteFile(filename+".bak", data, fmode)
	}
	dataout, count := ReplacePattern(data, ptn, repl, count)
	CheckErr(os.WriteFile(filename, dataout, fmode), "SearchReplaceFile WriteFile")
	return count
}

// Same as ReplacePattern but operates on string rather than []byte
func SearchReplaceString(instring, ptn, repl string, count int) string {
	o, _ := ReplacePattern([]byte(instring), ptn, repl, count)
	return string(o)
}

type LineInfileOpt struct {
	Insertafter   string
	Insertbefore  string
	Line          string
	LineNo        int
	Path          string
	Regexp        string
	Search_string string
	State         string
	Backup        bool
	ReplaceAll    bool
}

func NewLineInfileOpt(opt *LineInfileOpt) *LineInfileOpt {
	if opt.State == "" {
		opt.State = "present"
	}
	return opt
}

// Simulate ansible lineinfile module. There are some difference intentionaly to avoid confusing behaviour and reduce complexbility
// No option backref, the default behaviour is yes. That is when Regex is set it never add new line. To add new line use search_string or insert_after, insert_before opts.
// TODO bugs still when state=absent :P
func LineInFile(filename string, opt *LineInfileOpt) (err error, changed bool) {
	var returnFunc = func(err error, changed bool) (error, bool) {
		if !changed || !opt.Backup {
			os.Remove(filename + ".bak")
		}
		return err, changed
	}
	if opt.State == "" {
		opt.State = "present"
	}
	finfo, err := os.Stat(filename)
	if err1 := CheckErrNonFatal(err, "LineInFile Stat"); err1 != nil {
		return err1, false
	}
	fmode := finfo.Mode()
	if !(fmode.IsRegular()) {
		return fmt.Errorf("LineInFile: non-regular destination file %s", filename), false
	}
	if opt.Search_string != "" && opt.Regexp != "" {
		panic("[ERROR] conflicting option. Search_string and Regexp can not be both set")
	}
	if opt.Insertafter != "" && opt.Insertbefore != "" {
		panic("[ERROR] conflicting option. Insertafter and Insertbefore can not be both set")
	}
	if opt.LineNo > 0 && opt.Regexp != "" {
		panic("[ERROR] conflicting option. LineNo and Regexp can not be both set")
	}
	data, err := os.ReadFile(filename)
	if err1 := CheckErrNonFatal(err, "LineInFile ReadFile"); err1 != nil {
		return err1, false
	}

	if opt.Backup && opt.State != "print" {
		os.WriteFile(filename+".bak", data, fmode)
	}
	changed = false
	optLineB := []byte(opt.Line)
	datalines := bytes.Split(data, []byte("\n"))
	// ansible lineinfile is confusing. If set search_string and insertafter or inserbefore if search found the line is replaced and the other options has no effect. Unless search_string is not found then they will do it. Why we need that?
	// Basically the priority is search_string == regexp (thus they are mutually exclusive); and then insertafter or before. They can be all regex except search_string
	// If state is absent it remove all line matching the string, ignore the `line` param
	processAbsentLines := func(line_exist_idx map[int]interface{}, index_list []int, search_string_found bool) (error, bool) {
		d, d2 := []string{}, map[int]string{}
		// fmt.Printf("DEBUG line_exist_idx %v index_list %v search_string_found %v\n", line_exist_idx, index_list, search_string_found)
		if len(line_exist_idx) == 0 && len(index_list) == 0 {
			return nil, false
		}
		for idx, l := range datalines {
			_l := string(l)
			d = append(d, _l)
			// line_exist_idx output of the case of matched the whole line
			if _, ok := line_exist_idx[idx]; ok {
				d2[idx] = _l
			}
		}
		// index_list is the outcome of the search_string/regex opt (search raw string).
		for _, idx := range index_list {
			if search_string_found {
				d2[idx] = d[idx] // remember the value to this map
			}
		}
		// fmt.Printf("DEBUG d2 %s\n", JsonDump(d2, "  "))
		if opt.State == "print" {
			o := map[string]interface{}{
				"file":          filename,
				"matched_lines": d2,
			}
			fmt.Printf("%s\n", JsonDump(o, "  "))
		} else {
			for _, v := range d2 { // then remove by val here.
				d = RemoveItemByVal(d, v)
			}
			os.WriteFile(filename, []byte(strings.Join(d, "\n")), fmode)
		}
		return nil, true
	}
	// Now we process case by case
	if opt.Search_string != "" || opt.LineNo > 0 { // Match the whole line or we have line number. This is derterministic behaviour
		search_string_found, line_exist_idx := true, map[int]interface{}{}
		index_list := []int{}
		if opt.LineNo > 0 { // If we have line number we ignore the search string to be fast
			index_list = append(index_list, opt.LineNo-1)
		} else {
			for idx, lineb := range datalines {
				if bytes.Contains(lineb, []byte(opt.Search_string)) {
					index_list = append(index_list, idx)
				}
				if bytes.Equal(lineb, optLineB) { // Line already exists
					if opt.State == "present" {
						return returnFunc(nil, changed)
					} else {
						if !bytes.Equal(optLineB, []byte("")) {
							line_exist_idx[idx] = nil
						}
					}
				}
			}
		}
		if len(index_list) == 0 { // Did not find any search string. Will look insertafter  and before
			search_string_found = false
			ptnstring := opt.Insertafter
			if ptnstring == "" {
				ptnstring = opt.Insertbefore
			}
			if ptnstring != "" {
				ptn := regexp.MustCompile(ptnstring)
				for idx, lineb := range datalines {
					if ptn.Match(lineb) {
						index_list = append(index_list, idx)
					}
				}
			}
		}
		if len(index_list) == 0 && len(line_exist_idx) == 0 {
			// Can not find any insert_XXX match. Just add a new line at the end by setting this to the last
			index_list = append(index_list, len(datalines)-1)
		}
		switch opt.State {
		case "absent":
			return returnFunc(processAbsentLines(line_exist_idx, index_list, search_string_found))
		case "present":
			last := index_list[len(index_list)-1]
			if search_string_found {
				if !opt.ReplaceAll {
					datalines[last] = optLineB
				} else {
					for _, idx := range index_list {
						datalines[idx] = optLineB
					}
				}
			} else {
				if opt.Insertafter != "" {
					datalines = InsertItemAfter(datalines, last, optLineB)
				} else if opt.Insertbefore != "" {
					datalines = InsertItemBefore(datalines, last, optLineB)
				} else { // to the end as always
					datalines = InsertItemAfter(datalines, last, optLineB)
				}
			}
			os.WriteFile(filename, []byte(bytes.Join(datalines, []byte("\n"))), fmode)
			changed = true
		case "print":
			return returnFunc(processAbsentLines(line_exist_idx, index_list, search_string_found))
		}
	}
	// Assume the behaviour is the same as search_string for Regex, just it is a regex now. So if it matches then the line matched will be replaced. If no match then process the insertbefore or after
	if opt.Regexp != "" {
		search_string_found := true
		regex_ptn := regexp.MustCompile(opt.Regexp)
		index_list := []int{}
		matchesMap := map[int][][]byte{}
		line_exist_idx := map[int]interface{}{}

		for idx, lineb := range datalines {
			matches := regex_ptn.FindSubmatch(lineb)
			if len(matches) > 0 || matches != nil {
				index_list = append(index_list, idx)
				matchesMap[idx] = matches
			}
		}
		if len(index_list) == 0 { // Did not find any search string. Will look insertafter  and before
			search_string_found = false
			for idx, lineb := range datalines {
				if bytes.Equal(lineb, optLineB) { // Line already exists
					if opt.State == "present" {
						return returnFunc(nil, changed)
					} else {
						if !bytes.Equal(optLineB, []byte("")) {
							line_exist_idx[idx] = nil
						}
					}
				}
			}
			ptnstring := opt.Insertafter
			if ptnstring == "" {
				ptnstring = opt.Insertbefore
			}
			if ptnstring == "" {
				return returnFunc(nil, false)
			}
			ptn := regexp.MustCompile(ptnstring)
			for idx, lineb := range datalines {
				if ptn.Match(lineb) {
					index_list = append(index_list, idx)
				}
			}
		}
		if len(index_list) == 0 && len(line_exist_idx) == 0 {
			// Can not find any insert_XXX match. Just add a new line at the end by setting this to the last
			index_list = append(index_list, len(datalines)-1)
		}
		switch opt.State {
		case "absent":
			return returnFunc(processAbsentLines(line_exist_idx, index_list, search_string_found))
		case "present":
			last := index_list[len(index_list)-1]
			if search_string_found {
				// Expanding submatch
				if !opt.ReplaceAll {
					for i, submatch := range matchesMap[last] {
						if submatch != nil {
							placeholder := fmt.Sprintf("$%d", i)
							optLineB = bytes.Replace(optLineB, []byte(placeholder), submatch, -1)
						}
					}
					datalines[last] = optLineB
				} else {
					for _, line := range index_list {
						for i, submatch := range matchesMap[line] {
							if submatch != nil {
								placeholder := fmt.Sprintf("$%d", i)
								optLineB = bytes.Replace(optLineB, []byte(placeholder), submatch, -1)
								datalines[line] = optLineB
							}
						}
					}
				}
			} else {
				if opt.Insertafter != "" {
					datalines = InsertItemAfter(datalines, last, optLineB)
				} else if opt.Insertbefore != "" {
					datalines = InsertItemBefore(datalines, last, optLineB)
				} else { // Insert to the last then :P
					datalines = InsertItemAfter(datalines, last, optLineB)
				}
			}
			os.WriteFile(filename, []byte(bytes.Join(datalines, []byte("\n"))), fmode)
			changed = true
		case "print":
			return returnFunc(processAbsentLines(line_exist_idx, index_list, search_string_found))
		}
	}
	return err, changed
}

// InsertItemBefore inserts an item into a slice before a specified index
func InsertItemBefore[T any](slice []T, index int, item T) []T {
	if index < 0 || index > len(slice) {
		panic("InsertItemBefore: index out of range")
	}
	slice = append(slice[:index], append([]T{item}, slice[index:]...)...)
	return slice
}

// InsertItemAfter inserts an item into a slice after a specified index
func InsertItemAfter[T any](slice []T, index int, item T) []T {
	if index < -1 || index >= len(slice) {
		panic("InsertItemAfter: index out of range")
	}
	slice = append(slice[:index+1], append([]T{item}, slice[index+1:]...)...)
	return slice
}

func IsBinaryFile(filePath string) (bool, error) {
	// Open the file
	file, err := os.Open(filePath)
	if err != nil {
		return false, err
	}
	defer file.Close()

	// Read the first 512 bytes
	buffer := make([]byte, 512)
	n, err := file.Read(buffer)
	if err != nil {
		return false, err
	}

	// Detect the content type
	contentType := http.DetectContentType(buffer[:n])

	// Check if the content type indicates a binary file
	switch contentType {
	case "application/octet-stream", "application/x-executable", "application/x-mach-binary":
		return true, nil
	default:
		if len(contentType) > 0 && contentType[:5] == "text/" {
			return false, nil
		}
		return true, nil
	}
}

func IsBinaryFileSimple(filePath string) (bool, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return false, err
	}
	defer file.Close()

	buffer := make([]byte, 512)
	n, err := file.Read(buffer)
	if err != nil {
		return false, err
	}

	for i := 0; i < n; i++ {
		if buffer[i] == 0 {
			return true, nil
		}
		if buffer[i] < 0x20 && buffer[i] != 0x09 && buffer[i] != 0x0A && buffer[i] != 0x0D {
			return true, nil
		}
	}
	return false, nil
}

// CamelCaseToWords converts a camel case string into a list of words.
func CamelCaseToWords(s string) []string {
	var words []string
	runes := []rune(s)
	start := 0

	for i := 1; i < len(runes); i++ {
		if unicode.IsUpper(runes[i]) {
			words = append(words, string(runes[start:i]))
			start = i
		}
	}

	// Add the last word
	words = append(words, string(runes[start:]))

	return words
}

// ReadFirstLine read the first line in a file. Optimized for performance thus we do not re-use PickLinesInFile
// Also return the reader to the caller if caller need to
func ReadFirstLineWithPrefix(filePath string, prefix []string) (firstLine string, temp_file, matchedPrefix string, err error) {
	// Open the file
	file, err := os.Open(filePath)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()
	// Use a buffered reader for efficient reading
	reader := bufio.NewReader(file)
	// Read the first line
	firstLineB, _, err := reader.ReadLine()
	if err != nil {
		// Handle EOF as a valid case for files without newlines. This is not useful file but not an error case
		if err.Error() == "EOF" && len(firstLine) > 0 {
			return firstLine, "", "", errors.New("file has only one line so it should not be the config line | " + err.Error())
		}
		return "", "", "", fmt.Errorf("failed to read first line: %w", err)
	}
	firstLine = string(firstLineB)
	foundPrefix := false
	for _, p := range prefix {
		if strings.HasPrefix(firstLine, p) {
			foundPrefix = true
			matchedPrefix = p
			break
		}
	}
	if foundPrefix {
		tempFile, err1 := os.CreateTemp("", "restContent_*.txt")
		if err1 != nil {
			fmt.Println("Error creating temporary file:", err)
			return "", "", matchedPrefix, err1
		}
		defer tempFile.Close()

		// Copy the rest of the content from the reader to the temporary file
		_, err1 = io.Copy(tempFile, reader)
		if err1 != nil {
			fmt.Println("Error copying the rest of the content to the temporary file:", err)
			return "", "", matchedPrefix, err1
		}
		return firstLine, tempFile.Name(), matchedPrefix, nil
	} else {
		return "", "", matchedPrefix, fmt.Errorf("file does not have first line with these prefixes string")
	}
}

// PickLinesInFile - Pick some lines from a line number with count. If count is -1 pick to the end, -2 then to the end - 1 etc..
func PickLinesInFile(filename string, line_no, count int) (lines []string) {
	datab := Must(os.ReadFile(filename))

	datalines := strings.Split(string(datab), "\n")
	max_lines := len(datalines)
	switch {
	case count == 0:
		count = 1
	case count < 0:
		count = max_lines + count
	}

	start_index := line_no
	if start_index >= max_lines {
		return
	}
	end_index := start_index + count
	if end_index > max_lines-1 {
		end_index = max_lines - 1
	}
	return datalines[start_index:end_index]
}

// ExtractTextBlock extract a text from two set regex patterns. The text started with the line matched start_pattern
// and when hit the match for end_pattern it will stop not including_endlines
func ExtractTextBlock(filename string, start_pattern, end_pattern []string) (block string, start_line_no int, end_line_no int, datalines []string) {
	datab := Must(os.ReadFile(filename))
	datalines = strings.Split(string(datab), "\n")

	found_start, found_end := false, false
	all_lines_count := len(datalines)

	found_start, start_line_no, _ = SearchPatternListInStrings(datalines, start_pattern, 0, all_lines_count, 0)
	if found_start {
		if start_line_no == all_lines_count-1 {
			found_end, end_line_no = true, all_lines_count
		} else {
			found_end, end_line_no, _ = SearchPatternListInStrings(datalines, end_pattern, start_line_no+1, all_lines_count, 0)
		}
		if found_end {
			outputlines := datalines[start_line_no:end_line_no]
			return strings.Join(outputlines, "\n"), start_line_no, end_line_no, datalines
		}
	}
	return
}

// Extract a text block which contains marker which could be an int or a list of pattern. if it is an int it is the line number.
// First we get the text from the line number or search for a match to the upper pattern. If we found we will search down for the marker if it is defined, and when found, search for the lower_bound_pattern.
// The marker should be in the middle
// Return the text within the upper and lower, but not including the lower bound. Also return the line number range and full file content as datalines
// upper and lower is important; you can ignore marker by using a empty []string{}
func ExtractTextBlockContains(filename string, upper_bound_pattern, lower_bound_pattern []string, marker []string) (block string, start_line_no int, end_line_no int, datalines []string) {
	datab := Must(os.ReadFile(filename))
	datalines = strings.Split(string(datab), "\n")
	all_lines_count := len(datalines)

	found_upper, found_marker, found_lower := false, false, false

	found_upper, start_line_no, _ = SearchPatternListInStrings(datalines, upper_bound_pattern, 0, all_lines_count, 0)

	if !found_upper {
		return "", 0, 0, datalines
	}

	marker_line_no := 0
	if len(marker) > 0 {
		found_marker, marker_line_no, _ = SearchPatternListInStrings(datalines, marker, start_line_no+len(upper_bound_pattern), all_lines_count, 0)
		if !found_marker {
			return "", 0, 0, datalines
		}
	} else {
		marker_line_no = start_line_no
	}

	found_lower, end_line_no, _ = SearchPatternListInStrings(datalines, lower_bound_pattern, marker_line_no+len(marker), all_lines_count, 0)

	if !found_lower {
		if strings.Contains(lower_bound_pattern[0], "EOF") {
			end_line_no = all_lines_count
		} else {
			return "", 0, 0, datalines
		}
	}
	return strings.Join(datalines[start_line_no:end_line_no], "\n"), start_line_no, end_line_no, datalines
}

// Given a list of string of regex pattern and a list of string, find the coninuous match in that input list and return the start line of the match and the line content
// max_line defined the maximum line to search; set to 0 to use the len of input lines which is full
// start_line is the line to start searching; set to 0 to start from begining
// start_line should be smaller than max_line
// direction is the direction of the search -1 is upward; otherwise is down. If it is not 0 then the value is used for the step jump while searching eg. 1 for every line, 2 for every
// 2 lines, -2 is backward every two lines
// If found match return true, the line no we match and the line content.
func SearchPatternListInStrings(datalines []string, pattern []string, start_line, max_line, direction int) (found_marker bool, start_line_no int, linestr string) {
	marker_ptn := []*regexp.Regexp{}
	for _, ptn := range pattern {
		marker_ptn = append(marker_ptn, regexp.MustCompile(ptn))
	}
	expect_count_ptn_found := len(marker_ptn)
	count_ptn_found := 0
	if max_line == 0 {
		max_line = len(datalines)
	}
	step := 1
	if direction != 0 { // Allow caller to set the step
		step = direction
	}
datalines_Loop:
	for idx := start_line; idx < max_line && idx >= 0; idx = idx + step {
		count_ptn_found = 0
		line := datalines[idx]
		// fmt.Fprintf(os.Stderr, "line:%d|step:%d - %s\n", idx, step, line)
		if marker_ptn[0].MatchString(line) { // Found first one. Lets look forward count_ptn_found-1 lines and see we got match
			count_ptn_found++
			for i := 1; i < expect_count_ptn_found; i++ {
				if idx+expect_count_ptn_found-1 >= max_line { // -1 because we already move 1 to get idx.
					// Can not look forward - out of bound. We reach end of line.
					break datalines_Loop
				}
				if marker_ptn[i].MatchString(datalines[idx+i]) {
					count_ptn_found++
				} else {
					continue datalines_Loop
				}
			}
			found_marker, start_line_no = count_ptn_found == expect_count_ptn_found, idx
			linestr = datalines[idx]
			return
		}
	}
	return
}

// ExtractLineInLines will find a line match a pattern with capture (or not). The pattern is in between a start pattern and end pattern to narrow down
// search range. Return the result of FindAllStringSubmatch func of the match line
// This is simpler as it does not support multiple pattern as a marker like the other func eg ExtractTextBlockContains so input should be small
// and pattern match should be unique. Use the other function to devide it into small range and then use this func.
// start and line can be the same pattern. Same as line and end; it will return the match of start (or end) pattern
func ExtractLineInLines(blocklines []string, start, line, end string) [][]string {
	p0, p1, p2 := regexp.MustCompile(start), regexp.MustCompile(line), regexp.MustCompile(end)
	found_start, found, found_end := false, false, false
	var l string
	// length := len(blocklines)
	for _, _l := range blocklines {
		if !found_start {
			found_start = p0.MatchString(_l)
			continue
		}
		if !found_end {
			found_end = p2.MatchString(_l)
		}
		if found_start && !found {
			found = p1.MatchString(_l)
			if found {
				l = _l
			}
		}
		if found_end {
			break
		}
	}
	if found {
		return p1.FindAllStringSubmatch(l, -1)
	} else {
		return nil
	}
}

// SplitTextByPattern splits a multiline text into sections based on a regex pattern.
// If includeMatch is true, the matching lines are included in the result.
// pattern should a multiline pattern like `(?m)^Header line.*`
func SplitTextByPattern(text, pattern string, includeMatch bool) []string {
	re := regexp.MustCompile(pattern)
	sections := []string{}

	switch includeMatch {
	case true:
		matches := re.FindAllStringIndex(text, -1)
		start := 0
		for _, match := range matches {
			if start < match[0] {
				_t := strings.TrimSpace(text[start:match[0]])
				if _t != "" {
					sections = append(sections, _t)
				}
				start = match[0]
			}
		}
		sections = append(sections, text[start:]) // Capture the remaining part of the text
	case false:
		splitText := re.Split(text, -1)
		for _, part := range splitText {
			part = strings.TrimSpace(part)
			if part != "" {
				sections = append(sections, part)
			}
		}
	}
	return sections
}

// Edit line in a set of lines using simple regex and replacement
func LineInLines(datalines []string, search_pattern string, replace string) (output []string) {
	search_pattern_ptn := regexp.MustCompile(search_pattern)
	for i := 0; i < len(datalines); i++ {
		datalines[i] = search_pattern_ptn.ReplaceAllString(datalines[i], replace)
	}
	return datalines
}

// Find a block text matching and replace content with replText. Return the old text block. Use ExtractTextBlockContains under the hood to get the text block, see that func for help.
// if not care about marker pass a empty slice []string{}.
// To be sure of accuracy all of pattern must be uniquely identified. Recommend to use full line matching (use anchor ^ and $). The lowerbound if in the pattern there is string EOF then even the lowerbound not found but we hit EOF it will still return match for the block. See example in the test function
func BlockInFile(filename string, upper_bound_pattern, lower_bound_pattern []string, marker []string, replText string, keepBoundaryLines bool, backup bool) (oldBlock string) {
	fstat, err := os.Stat(filename)
	if errors.Is(err, fs.ErrNotExist) {
		panic("[ERROR]BlockInFile File " + filename + " doesn't exist\n")
	}

	block, start_line_no, end_line_no, datalines := ExtractTextBlockContains(filename, upper_bound_pattern, lower_bound_pattern, marker)
	if block == "" {
		fmt.Fprintf(os.Stderr, "block not found - upper: %v | lower: %v | marker: %v\n", upper_bound_pattern, lower_bound_pattern, marker)
		return ""
	}

	var upPartLines, downPartLines []string
	delta_lines := len(upper_bound_pattern)

	if keepBoundaryLines {
		upPartLines = datalines[0 : start_line_no+delta_lines]
		downPartLines = datalines[end_line_no:]
	} else {
		upPartLines = datalines[0:start_line_no]
		downPartLines = datalines[end_line_no+1:]
	}
	if backup {
		os.WriteFile(filename+".bak", []byte(strings.Join(datalines, "\n")), fstat.Mode())
	}
	os.WriteFile(filename, []byte(strings.Join(upPartLines, "\n")+"\n"+replText+"\n"+strings.Join(downPartLines, "\n")), fstat.Mode())
	return block
}

// Function to recursively convert interface{} to JSON-compatible types
func convertInterface(value interface{}) interface{} {
	switch v := value.(type) {
	case map[interface{}]interface{}:
		return convertMap(v)
	case []interface{}:
		return convertSlice(v)
	default:
		return v
	}
}

// SplitFirstLine return the first line from a text block. Line ending can be unix based or windows based
// The rest of the block is return also as the second output
func SplitFirstLine(text string) (string, string) {
	// Handle both \n and \r\n newlines
	if idx := strings.IndexAny(text, "\r\n"); idx != -1 {
		// Determine if the newline is \r\n or \n
		if idx+1 < len(text) && text[idx] == '\r' && text[idx+1] == '\n' {
			return text[:idx], text[idx+2:] // Skip \r\n
		}
		return text[:idx], text[idx+1:] // Skip \n
	}
	return text, "" // If no newline, return the whole text as the first line
}

// Function to convert map[interface{}]interface{} to map[string]interface{}
func convertMap(m map[interface{}]interface{}) map[string]interface{} {
	newMap := make(map[string]interface{})
	for key, value := range m {
		strKey, ok := key.(string)
		if !ok {
			// Handle the case where the key is not a string
			// Here, we simply skip the key-value pair
			continue
		}
		newMap[strKey] = convertInterface(value)
	}
	return newMap
}

// Function to recursively convert slices
func convertSlice(s []interface{}) []interface{} {
	newSlice := make([]interface{}, len(s))
	for i, value := range s {
		newSlice[i] = convertInterface(value)
	}
	return newSlice
}

// Custom JSON marshalling function
func CustomJsonMarshal(v interface{}) ([]byte, error) {
	converted := convertInterface(v)
	return json.Marshal(converted)
}
func CustomJsonMarshalIndent(v interface{}, indent int) ([]byte, error) {
	converted := convertInterface(v)
	return json.MarshalIndent(converted, "", strings.Repeat(" ", indent))
}

// CreateDirTree take the directory structure from the source and create it in the target
// Path should be absolute path. They should not overlap to avoid recursive loop
func CreateDirTree(srcDirpath, targetRoot string) error {
	if isExist, err := FileExists(srcDirpath); !isExist || err != nil {
		panic(fmt.Sprintf("[ERROR] src '%s' does not exist\n", srcDirpath))
	}
	os.Chdir(srcDirpath)
	filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			fmt.Printf("prevent panic by handling failure accessing a path %q: %v\n", srcDirpath, err)
			return err
		}

		if d.IsDir() {
			fmt.Printf("Going to create path %s\n", path)
			CheckErr(os.MkdirAll(filepath.Join(targetRoot, path), 0755), "ERROR MkdirAll")
		}

		return nil
	})
	return nil
}

// CloneSliceOfMap
func CloneSliceOfMap(a []any) (output []any) {
	for _, item := range a {
		output = append(output, maps.Clone(item.(map[string]any)))
	}
	return
}

// MaskCredential RegexPattern
var MaskCredentialPattern *regexp.Regexp = regexp.MustCompile(`(?i)(password|token|pass|passkey|secret|secret_key|access_key|PAT)([:=]{1,1})[\s]*[^\s]+`)

// Mask all credentials pattern
func MaskCredential(inputstr string) string {
	return MaskCredentialPattern.ReplaceAllString(inputstr, "$1$2 *****")
}
