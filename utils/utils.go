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
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"math/big"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	nm "net/mail"
	"net/textproto"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/stvoidit/gosmtp"

	"github.com/hashicorp/logutils"
	jsoniter "github.com/json-iterator/go"
	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/net/publicsuffix"
	"gopkg.in/yaml.v2"
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

// GetMapByKey - we have LookupMap
var GetMapByKey = LookupMap

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

// type cryptoSource struct{}

// func (s cryptoSource) Seed(seed int64) {}

// func (s cryptoSource) Int63() int64 {
// 	return int64(s.Uint64() & ^uint64(1<<63))
// }

// func (s cryptoSource) Uint64() (v uint64) {
// 	err := binary.Read(rand.Reader, binary.BigEndian, &v)
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	return v
// }

// MakePassword -
func MakePassword(length int) string {
	b := make([]byte, length)
	// seededRand := rand.New(rand.NewSource(time.Now().UnixNano() ))
	const charset = `abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_-+=`
	for i := range b {
		b[i] = charset[MakeRandNum(len(charset))]
	}
	return string(b)
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

// GetRequestValue - Attempt to get a val by key from the request in all cases.
// First from the mux variables in the route path such as /dosomething/{var1}/{var2}
// Then check the query string values such as /dosomething?var1=x&var2=y
// Then check the form values if any
// Then check the default value if supplied to use as return value
// For performance we split each type into each function so it can be called independantly
func GetRequestValue(r *http.Request, key ...string) string {
	o := GetQueryValue(r, key[0], "")
	if o == "" {
		o = GetFormValue(r, key[0], "")
	}
	if o == "" {
		if len(key) > 1 {
			o = key[1]
		} else {
			o = ""
		}
	}
	return o
}

// GetFormValue -
func GetFormValue(r *http.Request, key ...string) string {
	val := r.FormValue(key[0])
	if val == "" {
		if len(key) > 1 {
			return key[1]
		}
	}
	return val
}

// GetQueryValue -
func GetQueryValue(r *http.Request, key ...string) string {
	vars := r.URL.Query()
	val, ok := vars[key[0]]
	if !ok {
		if len(key) > 1 {
			return key[1]
		}
		return ""
	}
	return val[0]
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
	os.MkdirAll(dest, 0755)
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

// golang template helper Format
func Format(tmplStr string, data interface{}) string {
	var buff bytes.Buffer
	template.Must(template.New("").Parse(tmplStr)).Execute(
		&buff,
		data,
	)
	return buff.String()
}

func FindAndParseTemplates(rootDir, fileExtention string, funcMap template.FuncMap) (*template.Template, []string, error) {
	cleanRoot := filepath.Clean(rootDir)
	if fileExtention == "" {
		fileExtention = ".html"
	}
	pfx := len(cleanRoot) + 1
	root := template.New("")
	templateNameList := []string{}

	err := filepath.Walk(cleanRoot, func(path string, info os.FileInfo, e1 error) error {
		if !info.IsDir() && strings.HasSuffix(path, fileExtention) {
			if e1 != nil {
				return e1
			}
			b, e2 := os.ReadFile(path)
			if e2 != nil {
				return e2
			}
			name := path[pfx:]
			t := root.New(name).Funcs(funcMap)
			_, e2 = t.Parse(string(b))
			if e2 != nil {
				return e2
			}
			templateNameList = append(templateNameList, name)
		}
		return nil
	})
	return root, templateNameList, err
}
func ReadFileToBase64Content(filename string) string {
	f, _ := os.Open(filename)
	reader := bufio.NewReader(f)
	content, _ := io.ReadAll(reader)
	// Encode as base64.
	return base64.StdEncoding.EncodeToString(content)
}
func SendMailSendGrid(from, to, subject, plainTextContent, htmlContent string, attachments []string) error {
	addr, err := nm.ParseAddress(from)
	if err != nil {
		return err
	}
	mailfrom := mail.NewEmail(addr.Name, addr.Address)
	addr, err = nm.ParseAddress(to)
	if err != nil {
		return err
	}
	mailto := mail.NewEmail(addr.Name, addr.Address)
	message := mail.NewSingleEmail(mailfrom, subject, mailto, plainTextContent, htmlContent)
	for _, filepath := range attachments {
		filename := path.Base(filepath)
		message = message.AddAttachment(&mail.Attachment{
			Filename: filename,
			Content:  ReadFileToBase64Content(filepath),
		})
	}
	client := sendgrid.NewSendClient(os.Getenv("SENDGRID_API_KEY"))
	response, err := client.Send(message)
	if err != nil {
		log.Printf("[DEBUG] %v", err)
	} else {
		fmt.Printf("[DEBUG] %v", response.StatusCode)
		fmt.Printf("[DEBUG] %v", response.Body)
		fmt.Printf("[DEBUG] %v", response.Headers)
	}
	return err
}

// Sendmail
func SendMail(from string, to []string, subject string, message string, attachments []string, server, username, password string) error {
	client := gosmtp.NewSender(
		username,
		password,
		from,
		server)
	//for _, recs := range to {
	var msg = gosmtp.NewMessage().
		SetTO(to...).
		SetSubject(subject).
		SetText(message).
		AddAttaches(attachments...)
	if err := client.SendMessage(msg); err != nil {
		return err
	}
	//}
	return nil
}
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
func GenRandomString(n int) string {
	return MakePassword(n)
	// mrand.Seed(time.Now().UnixNano())
	// b := make([]byte, n)
	// for i := range b {
	// 	b[i] = LetterBytes[mrand.Intn(len(LetterBytes))]
	// }
	// return string(b)
}

func GenRandomStringV2(n int) string {
	b := make([]string, n)
	rand_nums := GetRandomNumberUseQrng(n)
	fmt.Printf("DEBUG: %v\n", rand_nums)
	LetterBytesLength := len(LetterBytes)
	if len(rand_nums) > 0 {
		for idx, i := range rand_nums {
			b[idx] = string(LetterBytes[i%LetterBytesLength])
		}
		return strings.Join(b, "")
	}
	return "ERROR"
}

// OK seems ANU is too scared of abuse, even using with api key it still limit reqeust severely. Offer no so much value unless we need to buy? Yuk!
func GetRandomNumberUseQrng(length int) []int {
	api_key := os.Getenv("QRNG_API_KEY")
	var qrng_url string
	var curl_header []string = []string{}
	if api_key != "" {
		log.Println("DEBUG Use quantum rng")
		qrng_url = fmt.Sprintf("https://api.quantumnumbers.anu.edu.au?length=%d&type=uint16", length)
		curl_header = []string{fmt.Sprintf("x-api-key:%s", api_key)}
	} else {
		qrng_url = fmt.Sprintf("https://qrng.anu.edu.au/API/jsonI.php?length=%d&type=uint16", length)
	}
	output := struct {
		Data_type string `json:"type"`
		Length    string `json:"length"`
		Data      []int  `json:"data"`
		Success   bool   `json:"success"`
	}{}
	if output_json, err := Curl("GET", qrng_url, "", "", curl_header); err == nil {
		log.Println(output_json)
		if err := json.Unmarshal([]byte(output_json), &output); err == nil {
			if output.Success {
				return output.Data
			}
		} else { // Old API, will remove soon
			output1 := struct {
				Data_type string `json:"type"`
				Length    int    `json:"length"`
				Data      []int  `json:"data"`
				Success   bool   `json:"success"`
			}{}
			if err := json.Unmarshal([]byte(output_json), &output1); err == nil {
				if output.Success {
					return output.Data
				}
			} else { //All error
				fmt.Printf("Error Unmarshal %s\nInput: '%s'\n", err, output_json)
			}
		}
	} else {
		fmt.Printf("Error GET %s -  %v\n", qrng_url, err)
	}
	return []int{}
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
func RemoveDuplicateStr(strSlice []string) []string {
	allKeys := make(map[string]bool)
	list := []string{}
	for _, item := range strSlice {
		if _, value := allKeys[item]; !value {
			allKeys[item] = true
			list = append(list, item)
		}
	}
	return list
}
func RemoveDuplicateInt(strSlice []int) []int {
	allKeys := make(map[int]bool)
	list := []int{}
	for _, item := range strSlice {
		if _, value := allKeys[item]; !value {
			allKeys[item] = true
			list = append(list, item)
		}
	}
	return list
}
func RemoveDuplicate(strSlice []interface{}) []interface{} {
	allKeys := make(map[interface{}]bool)
	list := []interface{}{}
	for _, item := range strSlice {
		if _, value := allKeys[item]; !value {
			allKeys[item] = true
			list = append(list, item)
		}
	}
	return list
}
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

func ParseConfig(configFile string) map[string]interface{} {
	if configFile == "" {
		log.Fatalf("Config file required. Run with -h for help")
	}
	configDataBytes, err := os.ReadFile(configFile)
	CheckErr(err, "ParseConfig")
	config := map[string]interface{}{}
	err = json.Unmarshal(configDataBytes, &config)
	if CheckErrNonFatal(err, "ParseConfig json.Unmarshal") != nil {
		err = yaml.Unmarshal(configDataBytes, &config)
		CheckErr(err, "ParseConfig yaml.Unmarshal")
	}
	return config
}

func Ternary(expr bool, x, y interface{}) interface{} {
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

func ConfigureLogging(w *os.File) {
	if w == nil {
		w = os.Stderr
	}
	defaultLogLevel := os.Getenv("LOG_LEVEL")
	if defaultLogLevel == "" {
		defaultLogLevel = "ERROR"
	}
	logFilter := &logutils.LevelFilter{
		Levels:   []logutils.LogLevel{"DEBUG", "INFO", "WARN", "ERROR"},
		MinLevel: logutils.LogLevel(defaultLogLevel),
		Writer:   w,
	}
	log.SetOutput(logFilter)
}

func RunSystemCommand(cmd string, verbose bool) string {
	if verbose {
		log.Printf("[INFO] command: %s\n", cmd)
	}
	command := exec.Command("bash", "-c", cmd)

	combinedOutput, err := command.CombinedOutput()
	if err != nil {
		log.Fatalf("[ERROR] error command: '%s' - %v\n    %s\n", cmd, err, combinedOutput)
	}
	output1 := fmt.Sprintf("%s", command.Stdout)
	output1 = strings.TrimSuffix(output1, "\n")
	return output1
}
func RunSystemCommandV2(cmd string, verbose bool) (string, error) {
	if verbose {
		log.Printf("[INFO] command: %s\n", cmd)
	}
	command := exec.Command("bash", "-c", cmd)

	combinedOutput, err := command.CombinedOutput()
	if err != nil {
		return fmt.Sprintf("[ERROR] error command: '%s' - %v\n    %s\n", cmd, err, combinedOutput), err
	}
	output1 := fmt.Sprintf("%s", command.Stdout)
	output1 = strings.TrimSuffix(output1, "\n")
	return output1, nil
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
		log.Printf("[ERROR] at %s - %v. IGNORED\n", location, err)
	}
	return err
}
func CheckNonErrIfMatch(err error, ptn, location string) error {
	if err != nil {
		if strings.Contains(err.Error(), ptn) {
			return err
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

	if caCertPool != nil || cert != nil {
		if CURL_DEBUG == "yes" {
			log.Printf("[DEBUG] going to create tlsConfig with caCertPool '%v' - cert '%v'\n", caCertPool, cert)
		}
		tlsConfig = &tls.Config{InsecureSkipVerify: InsecureSkipVerify.(bool)}

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
		log.Printf("[DEBUG] tls config %v\n", tlsConfig)
		log.Printf("[DEBUG] ca_cert_file '%v' - ssl_key_file '%v' ssl_cert_file '%v' insecureSkipVerify %v\n", ca_cert_file, ssl_key_file, ssl_cert_file, InsecureSkipVerify.(bool))
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
// This is not working for RP basically golang somehow send it using : Content type 'application/octet-stream' (or the server complain about that not supported). There are two parts each of them has different content type and it seems golang implementation does not fully support it? (the jsonPaths must be application-json).
// Forwhatever it is, even the header printed out correct - server complain. Curl work though so we will use curl for now
// I think golang behaviour is correct it should be 'application/octet-stream' for the file part, but the RP java server does not behave.
// So we add a manual set heasder map in for this case
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

// Add or delete attrbs set in a to b
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

// RemoveItem This func is depricated. Remove an item of the index i in a slice
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

func LookupMap(m map[string]interface{}, key string, default_val interface{}) interface{} {
	if v, ok := m[key]; ok {
		return v
	} else {
		return default_val
	}
}

var MapLookup = LookupMap

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
