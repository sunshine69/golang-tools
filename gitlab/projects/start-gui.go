package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"time"
	. "localhost.com/gitlab/model"
	u "localhost.com/utils"
	"github.com/goji/httpauth"
	"github.com/gorilla/mux"
	_ "github.com/mattn/go-sqlite3"
	"github.com/mileusna/crontab"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)
type ServerConfig struct {
	AuthUser     string
	SharedToken  string
	Port         string
	Serverdomain string
	SslKey       string
	SslCert      string
	Logdbpath    string
	Dbtimeout    string
	LogRetention string
}
var (
	WebSrvConfig  ServerConfig = ServerConfig{}
	version string
)

func homePage(w http.ResponseWriter, r *http.Request) {

}

func ContainerStatus(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "OK")
}

func GetVersion(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, version)
}

//HandleRequests -
func HandleRequests() {
	router := mux.NewRouter()
	router.HandleFunc("/", homePage).Methods("GET")
	if WebSrvConfig.SharedToken == "" {
		log.Printf("[WARN] - SharedToken is not set. Log server will allow anyone to put log in\n")
	} else {
		router.HandleFunc("/version", GetVersion).Methods("GET")
		//k8s container probe
		router.HandleFunc("/container_status", ContainerStatus).Methods("GET")
	}
	srv := &http.Server{
		Addr: fmt.Sprintf(":%s", WebSrvConfig.Port),
		// Good practice to set timeouts to avoid Slowloris attacks.
		WriteTimeout: time.Second * 15,
		ReadTimeout:  time.Second * 15,
		IdleTimeout:  time.Second * 60,
		Handler:      httpauth.SimpleBasicAuth(WebSrvConfig.AuthUser, WebSrvConfig.SharedToken)(router), // Pass our instance of gorilla/mux in.
	}
	// srv.Handler = gzhttp.GzipHandler(router)
	sslKey, sslCert := WebSrvConfig.SslKey, WebSrvConfig.SslCert
	if sslKey == "" {
		log.Printf("Start server on port %s\n", WebSrvConfig.Port)
		log.Fatal(srv.ListenAndServe())
	} else {
		if sslKey == "auto" {
			client := &acme.Client{DirectoryURL: autocert.DefaultACMEDirectory}
			// client := &acme.Client{DirectoryURL: "https://acme-staging-v02.api.letsencrypt.org/directory" }
			certManager := autocert.Manager{
				Prompt:     autocert.AcceptTOS,
				Cache:      autocert.DirCache("certs"),
				HostPolicy: autocert.HostWhitelist(WebSrvConfig.Serverdomain),
				Client:     client,
			}
			srv.TLSConfig = &tls.Config{
				GetCertificate: certManager.GetCertificate,
			}
			go http.ListenAndServe(":80", certManager.HTTPHandler(nil))
			log.Printf("Start SSL/TLS server with letsencrypt enabled on port %s\n", WebSrvConfig.Port)
			log.Fatal(srv.ListenAndServeTLS("", ""))
		} else {
			log.Printf("Start SSL/TLS server on port %s\n", WebSrvConfig.Port)
			log.Fatal(srv.ListenAndServeTLS(sslCert, sslKey))
		}
	}
}
func StartWebGUI() {
	RunScheduleTasks()
	HandleRequests()
}
// TODO
func RunScheduleTasks() {
	ctab := crontab.New() // create cron table
	// AddJob and test the errors
	if err := ctab.AddJob("1 0 1 * *", DatabaseMaintenance); err != nil {
		log.Printf("[WARN] - Can not add maintanance job - %v\n", err)
	}
}
// TODO
func DatabaseMaintenance() {
	conn := GetDBConn()
	defer conn.Close()
	start, _ := u.ParseTimeRange(WebSrvConfig.LogRetention, "")
	_startTime := start.Format("2006-01-02 15:04:05.999")
	_, err := conn.Exec(fmt.Sprintf(
		`DELETE FROM log WHERE ts < "%s";
	`, _startTime))
	if err != nil {
		log.Printf("[ERROR] - can not delete old data - %v\n", err)
	}
}
