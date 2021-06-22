package utils

import (
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
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	jsoniter "github.com/json-iterator/go"
)

//TimeISO8601LayOut
const (
	TimeISO8601LayOut = "2006-01-02T15:04:05-0700"
	AUTimeLayout      = "02/01/2006 15:04:05 MST"
)

var (
	json = jsoniter.ConfigCompatibleWithStandardLibrary
)

func RunSystemCommand(cmd string, verbose bool) string {
	if verbose {
		log.Printf("command: %s\n", cmd)
	}
	command := exec.Command("bash", "-c", cmd)

	combinedOutput, err := command.CombinedOutput()
	if err != nil {
		log.Fatalf("error command: '%s' - %v\n    %s\n", cmd, err, combinedOutput)
	}
	output1 := fmt.Sprintf("%s", command.Stdout)
	output1 = strings.TrimSuffix(output1, "\n")
	return output1
}

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
func JsonDump(obj map[string]interface{}, indent string) string {
	if indent == "" {
		indent = "    "
	}
	msgByte, err := json.MarshalIndent(obj, "", indent)
	if CheckErr(err, "JsonDump") {
		return string(msgByte)
	}
	return ""
}

//Given a duration as string return two time object the second one is now, the first one is the past
//so that the time delta is equal the duration
func ParseTimeRange(durationStr, tz string) (time.Time, time.Time) {
	var start, end time.Time
	if tz == "" {
		tz, _ = time.Now().Zone()
	}
	timerangePtn := regexp.MustCompile(`([\d]{2,2}/[\d]{2,2}/[\d]{4,4} [\d]{2,2}:[\d]{2,2}:[\d]{2,2}) - ([\d]{2,2}/[\d]{2,2}/[\d]{4,4} [\d]{2,2}:[\d]{2,2}:[\d]{2,2})`)
	dur, e := time.ParseDuration(durationStr)
	if e != nil {
		log.Printf("ERROR can not parse duration string using time.ParseDuration for %s - %v. Will try next\n", durationStr, e)
		m := timerangePtn.FindStringSubmatch(durationStr)
		if len(m) != 3 {
			log.Printf("ERROR Can not parse duration. Set default to 15m ago - %v", e)
			dur, _ = time.ParseDuration("15m")
		} else {
			start, _ = time.Parse(AUTimeLayout, m[1]+" "+tz)
			end, _ = time.Parse(AUTimeLayout, m[2]+" "+tz)
		}
	} else {
		end = time.Now()
		start = end.Add(-1 * dur)
	}
	// log.Printf("Time range: %s - %s\n",start.Format(AUTimeLayout), end.Format(AUTimeLayout))
	return start, end
}
func CheckErr(err error, location string) bool {
	if err != nil {
		log.Fatalf("ERROR at %s - %v\n", location, err)
		return false
	} else {
		return true
	}
}
func CheckErrNonFatal(err error, location string) bool {
	if err != nil {
		log.Printf("ERROR at %s - %v. IGNORED\n", location, err)
		return false
	} else {
		return true
	}
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
func RemoveItem(s []interface{}, i int) []interface{} {
	s[i] = s[len(s)-1]
	// We do not need to put s[i] at the end, as it will be discarded anyway
	return s[:len(s)-1]
}

type AppConfigProperties map[string]string

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
func MakeRequest(method string, config map[string]interface{}, data []byte, jar *cookiejar.Jar) map[string]interface{} {
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
		log.Printf("ERROR Need the config['url']\n")
		return map[string]interface{}{}
	}
	req, err := http.NewRequest(method, _url, bytes.NewBuffer(data))
	CheckErr(err, "MakeRequest req")
	_token, ok := config["token"].(string)
	if ok {
		req.Header.Set("Authorization", fmt.Sprintf("%s", _token))
	}
	headers, ok := config["headers"].(map[string]string)
	if ok {
		for k, v := range headers {
			req.Header.Set(k, v)
		}
	}
	resp, err := client.Do(req)
	CheckErr(err, "MakeRequest client.Do")
	defer resp.Body.Close()
	content, err := ioutil.ReadAll(resp.Body)
	CheckErr(err, "MakeRequest Readall")
	if content[0] == []byte("[")[0] {
		var m []interface{}
		CheckErr(json.Unmarshal(content, &m), "MakeRequest Unmarshall")
		return map[string]interface{}{
			"results": m,
		}
	} else {
		m := map[string]interface{}{}
		CheckErr(json.Unmarshal(content, &m), "MakeRequest Unmarshall")
		return m
	}
}
