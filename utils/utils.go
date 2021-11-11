package utils

import (
	"archive/zip"
	"html/template"
	"path/filepath"
	"errors"
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/textproto"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
	"golang.org/x/net/publicsuffix"
	"github.com/hashicorp/logutils"
	jsoniter "github.com/json-iterator/go"
	"gopkg.in/yaml.v2"
	"database/sql"
	mr "math/rand"
	"encoding/base64"
	nm "net/mail"
	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
	"path"
)

//TimeISO8601LayOut
const (
	TimeISO8601LayOut = "2006-01-02T15:04:05-0700"
	AUTimeLayout      = "02/01/2006 15:04:05 MST"
	CleanStringDateLayout = "2006-01-02-150405"
	LetterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#%^()"
)

var (
	json = jsoniter.ConfigCompatibleWithStandardLibrary
)

func Unzip(zipfile, dst string) error {
    archive, err := zip.OpenReader(zipfile)
    if err != nil {
        return err
    }
    defer archive.Close()
    for _, f := range archive.File {
        filePath := filepath.Join(dst, f.Name)
        fmt.Println("unzipping file ", filePath)

        if !strings.HasPrefix(filePath, filepath.Clean(dst)+string(os.PathSeparator)) {
            fmt.Println("invalid file path")
            return nil
        }
        if f.FileInfo().IsDir() {
            fmt.Println("creating directory...")
            os.MkdirAll(filePath, os.ModePerm)
            continue
        }
        if err := os.MkdirAll(filepath.Dir(filePath), os.ModePerm); err != nil {
            return err
        }
        dstFile, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
        if err != nil {
            return err
        }
        fileInArchive, err := f.Open()
        if err != nil {
            return err
        }
        if _, err := io.Copy(dstFile, fileInArchive); err != nil {
            return err
        }
        dstFile.Close()
        fileInArchive.Close()
    }
	return nil
}

func FindAndParseTemplates(rootDir, fileExtention string,funcMap template.FuncMap) (*template.Template, []string, error) {
    cleanRoot := filepath.Clean(rootDir)
	if fileExtention == "" { fileExtention = ".html" }
    pfx := len(cleanRoot)+1
    root := template.New("")
	templateNameList := []string{}

    err := filepath.Walk(cleanRoot, func(path string, info os.FileInfo, e1 error) error {
        if !info.IsDir() && strings.HasSuffix(path, fileExtention) {
            if e1 != nil {
                return e1
            }
            b, e2 := ioutil.ReadFile(path)
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
    content, _ := ioutil.ReadAll(reader)
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
	for _, filepath := range attachments{
		filename := path.Base(filepath)
		message = message.AddAttachment(&mail.Attachment{
			Filename: filename,
			Content: ReadFileToBase64Content(filepath),
		} )
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
	mr.Seed(time.Now().UnixNano())
    b := make([]byte, n)
    for i := range b {
        b[i] = LetterBytes[mr.Intn(len(LetterBytes))]
    }
    return string(b)
}
func RunDSL(dbc *sql.DB, sql string) map[string]interface{}{
	stmt, err := dbc.Prepare(sql)
	if err != nil {return map[string]interface{}{"result":nil,"error": err}}
	defer stmt.Close()
	result, err := stmt.Exec()
	return map[string]interface{}{"result":result,"error": err}
}
// Run SELECT and return map[string]interface{}{"result": []interface{}, "error": error}
func RunSQL(dbc *sql.DB, sql string) map[string]interface{} {
	var result = make([]interface{}, 0)
	ptn := regexp.MustCompile(`[\s]+(from|FROM)[\s]+([^\s]+)[\s]*`)
	if matches := ptn.FindStringSubmatch(sql); len(matches) == 3 {
		stmt, err := dbc.Prepare(sql)
		if err != nil {return map[string]interface{}{"result":nil,"error": err}}
		defer stmt.Close()
		rows, err := stmt.Query()
		if err != nil {return map[string]interface{}{"result":nil,"error": err}}
		defer rows.Close()
		columnNames, err := rows.Columns() // []string{"id", "name"}
		if err != nil {return map[string]interface{}{"result":nil,"error": err}}
		columns := make([]interface{}, len(columnNames))
		columnTypes, _ := rows.ColumnTypes()
		columnPointers := make([]interface{}, len(columnNames))
		for i := range columns {
			columnPointers[i] = &columns[i]
		}
		for rows.Next() {
			err := rows.Scan(columnPointers...)
			if err != nil {return map[string]interface{}{"result":nil,"error": err}}
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
	configDataBytes, err := ioutil.ReadFile(configFile)
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
//Given a duration string return a tuple of start time, end time satisfy the duration.
//If duration string is dd/mm/yyyy hh:mm:ss - dd/mm/yyyy hh:mm:ss it simply return two time object.
//If duration is like 15m then endtime is now, start time is 15 minutes ago. This applies for all case if input is not parsable
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
		} else{
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
	client := http.Client{}
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
		content, err := ioutil.ReadAll(resp.Body)
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
	content, err := ioutil.ReadAll(resp.Body)
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
func Upload(client *http.Client, url string, values map[string]io.Reader, mimetype map[string]string, headers map[string]string) (err error) {
	// Prepare a form that you will submit to that URL.
	//This is not working for RP basically golang somehow send it using : Content type 'application/octet-stream' (or the server complain about that not supported). There are two parts each of them has different content type and it seems golang implementation does not fully support it? (the jsonPaths must be application-json).
	//Forwhatever it is, even the header printed out correct - server complain. Curl work though so we will use curl for now
	//I think golang behaviour is correct it should be 'application/octet-stream' for the file part, but the RP java server does not behave.
	//So we add a manual set heasder map in for this case
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
//Add or delete attrbs set in a to b
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
						b = RemoveItem(b, idxb)
						found = true
						continue
					}
				} else { //both key is nil
					if _a1["value"] == _b1["value"] {
						found = true
						if action == "add" {
							continue
						} else {
							b = RemoveItem(b, idxb)
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

func RemoveItem(s []interface{}, i int) []interface{} {
	s[i] = s[len(s)-1]
	// We do not need to put s[i] at the end, as it will be discarded anyway
	return s[:len(s)-1]
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

func LookupMap(m map[string]interface{}, key string, default_val string) interface{} {
	if v, ok := m[key]; ok {
		return v
	} else {
		return default_val
	}
}
var MapLookup = LookupMap

//Crypto utils

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
	if err := ioutil.WriteFile(fmt.Sprintf("%s.crt", keyfilename), out.Bytes(), 0640); err != nil {
		log.Fatalf("can not write public key %v\n", err)
	}

	out.Reset()
	pem.Encode(out, pemBlockForKey(priv))
	if err := ioutil.WriteFile(fmt.Sprintf("%s.key", keyfilename), out.Bytes(), 0600); err != nil {
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
// Pass an interface, return same interface if they are string as key or list of string as key
func ValidateInterfaceWithStringKeys(val interface{}) (interface{}, error) {
	switch val := val.(type) {
	case map[interface{}]interface{}:
		m := make(map[string]interface{})
		for k, v := range val {
			k, ok := k.(string)
			if !ok {
				return nil, errors.New(fmt.Sprintf("found non-string key '%v'", k))
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