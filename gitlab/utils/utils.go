package gitlabutils

import (
	"fmt"
	"log"
	"os"
	"path"

	"net/http"
	nm "net/mail"

	"github.com/hashicorp/logutils"
	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
	u "github.com/sunshine69/golang-tools/utils"
	"github.com/xanzy/go-gitlab"
)

func GetNameSpace(git *gitlab.Client, searchStr string) {
	nsService := git.Namespaces
	listNsOpt := &gitlab.ListNamespacesOptions{
		Search: gitlab.String(searchStr),
		ListOptions: gitlab.ListOptions{
			PerPage: 25,
			Page:    1,
		},
	}
	o, _, err := nsService.ListNamespaces(listNsOpt)
	u.CheckErr(err, "nsService.ListNamespaces")
	fmt.Printf("%s\n", u.JsonDump(o, "    "))
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
			Content:  u.ReadFileToBase64Content(filepath),
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
