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

func TestSha1Sum(t *testing.T) {
	o := Sha1Sum("1q2w3e")
	log.Println(o)
	Assert(o == "9ac20922b054316be23842a5bca7d69f29f69d77", "OK", true)
}

func TestSha256Sum(t *testing.T) {
	o := Sha256Sum("1q2w3e")
	log.Println(o)
	Assert(o == "c0c4a69b17a7955ac230bfc8db4a123eaa956ccf3c0022e68b8d4e2f5b699d1f", "OK", true)
}

func TestSha512Sum(t *testing.T) {
	o := Sha512Sum("1q2w3e")
	log.Println(o)
	Assert(o == "da2ca4a2b6616e28479a372752377f23a2361e1df855d881ac987341f837e3f260f6d5d68e40f0b1fb62d98e3309a3593b12314d6e7b91179642426709c5d6f5", "OK", true)
}

func TestBcryptHash(t *testing.T) {
	hashed, _ := BcryptHashPassword("1q2w3e", -1)
	log.Printf("Hash: %s\n", hashed)
	Assert(BcryptCheckPasswordHash("1q2w3e", hashed), "OK", false)
}

func TestSendMail(t *testing.T) {
	mypassword := Getenv("SMTP_PASSWORD", "")
	if mypassword == "" {
		log.Println("Need to set these env vars before running test. MAIL_FROM MAIL_TO MAIL_USER SMTP_PASSWORD. We use smtp.gmail.com:465 for the server. Test Skipped")
		return
	}
	from, to, user := Getenv("MAIL_FROM", ""), Getenv("MAIL_TO", ""), Getenv("MAIL_USER", "")
	err := SendMail(from, []string{to}, "test golang sendmail", "test content", []string{"utils.go"}, "smtp.gmail.com:465", user, mypassword)
	if err != nil {
		log.Fatalf("ERROR %v\n", err)
	}
}

// go test -timeout 30s -run '^TestCurl$'  -v
func TestCurl(t *testing.T) {
	o, err := Curl("GET", "https://kernel.org", "", "", []string{})
	CheckErr(err, "ERROR")
	log.Println(o)
}

func TestGetRandomNumberUseQrng(t *testing.T) {
	o := GetRandomNumberUseQrng(12)
	log.Println(o)
}
// Use https://www.nexcess.net/web-tools/secure-password-generator/ to test randomness it seems both version generates strong enough. No one wins over in terms of entropy though
func TestGenrateRandomStringV2(t *testing.T) {
	o := GenRandomStringV2(12)
	log.Println(o)
	o = GenRandomString(12)
	log.Println(o)
}
