package utils

import (
	"log"
	"testing"
)

func TestUtils(t *testing.T) {
	// o := RunSystemCommand("ls /", true)
	// fmt.Printf("OUT: %v\n", o)
	a := GenRandomString(12)
	log.Println(a)
}

// func TestUnzip(t *testing.T) {
// 	err := Unzip("Downloads/artifacts.zip", ".")
// 	CheckErr(err, "  ")
// }

func TestBcryptHash(t *testing.T) {
	hashed, _ := BcryptHashPassword("1q2w3e", -1)
	log.Printf("Hash: %s\n", hashed)
	Assert(BcryptCheckPasswordHash("1q2w3e", hashed), "OK", false)
}

func TestSendMail(t *testing.T) {
	mypassword := Getenv("SMTP_PASSWORD", "")
	if mypassword == "" {
		log.Fatal("Need to set these env vars before running test. MAIL_FROM MAIL_TO MAIL_USER SMTP_PASSWORD. We use smtp.gmail.com:465 for the server")
	}
	from, to, user := Getenv("MAIL_FROM", ""), Getenv("MAIL_TO", ""), Getenv("MAIL_USER", "")
	err := SendMail(from, []string{to}, "test golang sendmail", "test content", []string{"utils.go"}, "smtp.gmail.com:465", user, mypassword)
	if err != nil {
		log.Fatalf("ERROR %v\n", err)
	}
}
//go test -timeout 30s -run '^TestCurl$'  -v
func TestCurl(t *testing.T) {
	o, err := Curl("GET", "https://kernel.org", "", "", []string{})
	CheckErr(err, "ERROR")
	log.Println(o)
}
