package main

import (
	"crypto/subtle"
	"crypto/tls"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	_ "github.com/mattn/go-sqlite3"
	"github.com/mileusna/crontab"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
	. "localhost.com/gitlab/model"
	u "localhost.com/utils"
)

var (
	// AppConfig  map[string]interface{}
	version, SessionKey, SessionName string
	SessionStore                     *sessions.CookieStore
)

func homePage(w http.ResponseWriter, r *http.Request) {
	session, _ := SessionStore.Get(r, SessionName) //; u.CheckErr(err, "homePage store.Get")
	t := template.Must(template.New("home.html").ParseFiles("templates/home.html"))
	err := t.Execute(w, map[string]interface{}{
		"user":          session.Values["user"],
		"token":         session.Values["token"],
		"page_offset":   u.Ternary(session.Values["page_offset"] != nil, session.Values["page_offset"], "0"),
		"running_procs": u.RunSystemCommand("ls -lha /tmp/*.lock 2>/dev/null || true", false),
	})
	u.CheckErr(err, "homePage t.Execute")
}

func ContainerStatus(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "OK")
}
func GetVersion(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, version)
}

func RunFunction(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	ses, _ := SessionStore.Get(r, SessionName)
	user := ses.Values["user"].(string)
	func_name := vars["func_name"]
	git, SearchStr := GetGitlabClient(), ""
	lockFileName := fmt.Sprintf("/tmp/%s.lock", func_name)
	if ok, err := u.FileExists(lockFileName); ok && (err == nil) {
		fmt.Fprintf(w, "Process %s already running", func_name)
		return
	}
	_, err := os.Create(lockFileName)
	u.CheckErr(err, "UpdateAllWrapper create clock file")
	logFile := "RunFunction-" + func_name + "-" + ses.Values["user"].(string) + "-" + time.Now().Format(u.CleanStringDateLayout) + ".txt"
	f, err := os.OpenFile("log/"+logFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	u.CheckErr(err, "OpenFile Log") // Close file inside each go routine

	switch func_name {
	case "update-all":
		go func() {
			log.SetOutput(f)
			defer f.Close()
			defer log.SetOutput(os.Stdout)
			u.SendMailSendGrid("Go1 GitlabDomain Automation <steve.kieu@go1.com>", user, "GitlabDomain Automation - update-all", "", fmt.Sprintf("update-all Started. Please find the log attached or click <a href='%s/log/%s'>here</a>", r.Host, logFile), []string{"log/" + logFile})
			UpdateAllWrapper(git, SearchStr)
			os.Remove(lockFileName)
			u.SendMailSendGrid("Go1 GitlabDomain Automation <steve.kieu@go1.com>", user, "GitlabDomain Automation - update-all", "", fmt.Sprintf("update-all Completed. Please find the log attached or click <a href='%s/log/%s'>here</a>", r.Host, logFile), []string{"log/" + logFile})
		}()
	case "update-project":
		go func() {
			log.SetOutput(f)
			defer f.Close()
			defer log.SetOutput(os.Stdout)
			DumpOrUpdateProject(git, SearchStr)
			os.Remove(lockFileName)
		}()
	case "update-namespace":
		go func() {
			log.SetOutput(f)
			defer f.Close()
			defer log.SetOutput(os.Stdout)
			DumpOrUpdateNamespace(git, SearchStr)
			UpdateGroupMember(git)
			os.Remove(lockFileName)
		}()
	case "update-team":
		go func() {
			log.SetOutput(f)
			defer f.Close()
			defer log.SetOutput(os.Stdout)
			UpdateTeam()
			os.Remove(lockFileName)
		}()
	case "UpdateGitlabUser":
		go func() {
			log.SetOutput(f)
			defer f.Close()
			defer log.SetOutput(os.Stdout)
			UpdateGitlabUser(git)
			os.Remove(lockFileName)
		}()
	case "UpdateGroupMember":
		go func() {
			log.SetOutput(f)
			defer f.Close()
			defer log.SetOutput(os.Stdout)
			UpdateGroupMember(git)
			os.Remove(lockFileName)
		}()
	case "get-first10mr-peruser":
		go func() {
			log.SetOutput(f)
			defer f.Close()
			defer log.SetOutput(os.Stdout)
			Addhoc_getfirst10mrperuser(git)
			os.Remove(lockFileName)
		}()
	case "UpdateProjectDomainFromCSV":
		go func() {
			log.SetOutput(f)
			defer f.Close()
			defer log.SetOutput(os.Stdout)
			UpdateProjectDomainFromCSV("data/MigrationServices.csv")
			os.Remove(lockFileName)
		}()
	case "UpdateProjectDomainFromCSVSheet3":
		go func() {
			log.SetOutput(f)
			defer f.Close()
			defer log.SetOutput(os.Stdout)
			UpdateProjectDomainFromCSVSheet3("data/MigrationServices-sheet3.csv")
			os.Remove(lockFileName)
		}()
	case "UpdateProjectMigrationStatus":
		go func() {
			log.SetOutput(f)
			defer f.Close()
			defer log.SetOutput(os.Stdout)
			UpdateProjectMigrationStatus(git)
			os.Remove(lockFileName)
		}()
	case "UpdateProjectDomainFromExcelNext":
		go func() {
			log.SetOutput(f)
			defer f.Close()
			defer log.SetOutput(os.Stdout)
			u.SendMailSendGrid("Go1 GitlabDomain Automation <steve.kieu@go1.com>", user, "GitlabDomain Automation - UpdateProjectDomainFromExcelNext", "", fmt.Sprintf("UpdateProjectDomainFromExcelNext Started. Please find the log attached or click <a href='%s/log/%s'>here</a>", r.Host, logFile), []string{"log/" + logFile})

			u.RunSystemCommand("rm -rf data/GitlabProject-Domain-Status.xlsx || true; sleep 1; rclone sync onedrive:/GitlabProject-Domain-Status.xlsx data/", false)
			UpdateTeamDomainFromExelNext(git, "data/GitlabProject-Domain-Status.xlsx")
			UpdateProjectDomainFromExcelNext(git, "data/GitlabProject-Domain-Status.xlsx")
			UpdateGroupMember(git)
			os.Remove(lockFileName)

			u.SendMailSendGrid("Go1 GitlabDomain Automation <steve.kieu@go1.com>", user, "GitlabDomain Automation - UpdateProjectDomainFromExcelNext", "", fmt.Sprintf("UpdateProjectDomainFromExcelNext Completed. Please find the log attached or click <a href='%s/log/%s'>here</a>", r.Host, logFile), []string{"log/" + logFile})
		}()
	}
	fmt.Fprintf(w, "<p>Process %s started. You can see the log <a href='/log/%s'>here</a></p>", func_name, logFile)
}
func DisplayTransferProjectConsole(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	ses, _ := SessionStore.Get(r, SessionName)
	searchName := r.FormValue("keyword")
	migrated := r.FormValue("migrated")
	// ses.Values["migrated"] = migrated
	currentOffsetStr := u.Ternary(vars["page_offset"] != "" && searchName == "", vars["page_offset"], "0").(string)
	currentOffset, _ := strconv.Atoi(currentOffsetStr)
	sqlwhere := fmt.Sprintf(`project.namespace_kind = 'group' AND project.labels NOT LIKE '%%personal%%' AND is_active = 1 AND domain_ownership_confirmed = %s AND project.name LIKE '%%%s%%' AND project.pid IN (SELECT p.pid from project AS p, project_domain AS pd, domain AS d WHERE p.pid = pd.project_id AND pd.domain_id = d.gitlab_ns_id AND p.path_with_namespace NOT LIKE 'mirror/%%' AND p.path_with_namespace NOT LIKE 'disabled-microservices/%%' ) ORDER BY ts LIMIT 25 OFFSET %d`, migrated, searchName, currentOffset)
	projectList := ProjectGet(map[string]string{"where": sqlwhere})
	t := template.Must(template.New("project-migration.html").ParseFiles("templates/project-migration.html"))
	currentOffset = currentOffset + 25

	ses.Values["page_offset"] = currentOffset
	ses.Save(r, w)
	err := t.Execute(w, map[string]interface{}{
		"projects":    projectList,
		"page_offset": currentOffset,
		"user":        ses.Values["user"],
		"migrated":    migrated,
		"sqlwhere":    "SELECT * FROM project WHERE " + sqlwhere,
	})
	u.CheckErr(err, "homePage t.Execute")
	// log.Printf("%v\n", projectList)
}
func RunTransferProject(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	ses, _ := SessionStore.Get(r, SessionName)
	user := ses.Values["user"].(string)
	lockFileName := fmt.Sprintf("/tmp/RunTransferProject_%s.lock", vars["project_id"])
	logFile := "RunFunction-RunTransferProject_" + vars["project_id"] + "-" + user + "-" + time.Now().Format(u.CleanStringDateLayout) + ".txt"
	if ok, err := u.FileExists(lockFileName); ok && (err == nil) {
		previousLogfile, _ := ioutil.ReadFile(lockFileName)
		fmt.Fprintf(w, "RunTransferProject already running - lock file %s - <a href='/log/%s'>Log</a>", lockFileName, string(previousLogfile))
		return
	}
	ioutil.WriteFile(lockFileName, []byte(logFile), 0660)
	f, err := os.OpenFile("log/"+logFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	u.CheckErr(err, "RunTransferProject OpenFile logfile")
	go func(f *os.File) {
		log.SetOutput(f)
		defer f.Close()
		// defer log.SetOutput(os.Stdout) // no need to do that?
		git := GetGitlabClient()
		project_id, _ := strconv.Atoi(vars["project_id"])
		log.Printf("TransferProject Started with is %d - \n", project_id)

		u.SendMailSendGrid("Go1 GitlabDomain Automation <steve.kieu@go1.com>", user, fmt.Sprintf("ProjectID %d Migration Started", project_id), "", fmt.Sprintf("Please find the log attached or click <a href='%s/log/%s'>here</a>", r.Host, logFile), []string{"log/" + logFile})

		TransferProject(git, project_id, user)

		u.SendMailSendGrid("Go1 GitlabDomain Automation <steve.kieu@go1.com>", user, fmt.Sprintf("ProjectID %d Migration Status", project_id), "", fmt.Sprintf("Migration fully completed. Please find the log attached or click <a href='%s/log/%s'>here</a>", r.Host, logFile), []string{"log/" + logFile})
		os.Remove(lockFileName)
	}(f)
	fmt.Fprintf(w, "Started Project ID %s - <a href='/log/%s'>Log</a><br/>Also check your email for notification.", vars["project_id"], logFile)
}

//HandleRequests -
func HandleRequests() {
	router := mux.NewRouter()

	staticFS := http.FileServer(http.Dir("./log"))
	router.PathPrefix("/log/").Handler(BasicAuthHandler(http.StripPrefix("/log/", staticFS), AppConfig["AuthUser"].(string), AppConfig["SharedToken"].(string), "default realm"))

	router.HandleFunc("/", BasicAuth(homePage, AppConfig["AuthUser"].(string), AppConfig["SharedToken"].(string), "default realm")).Methods("GET")
	router.HandleFunc("/run/{func_name}", BasicAuth(RunFunction, AppConfig["AuthUser"].(string), AppConfig["SharedToken"].(string), "default realm")).Methods("POST")
	router.HandleFunc("/transferproject/{page_offset:[0-9]+}", BasicAuth(DisplayTransferProjectConsole, AppConfig["AuthUser"].(string), AppConfig["SharedToken"].(string), "default realm")).Methods("GET")
	router.HandleFunc("/runmigrate/{project_id:[0-9]+}", BasicAuth(RunTransferProject, AppConfig["AuthUser"].(string), AppConfig["SharedToken"].(string), "default realm")).Methods("POST")

	if AppConfig["SharedToken"].(string) == "" {
		log.Printf("[WARN] - SharedToken is not set. Log server will allow anyone to put log in\n")
	} else {
		router.HandleFunc("/version", GetVersion).Methods("GET")
		//k8s container probe
		router.HandleFunc("/container_status", ContainerStatus).Methods("GET")
	}
	srv := &http.Server{
		Addr: fmt.Sprintf(":%s", AppConfig["Port"].(string)),
		// Good practice to set timeouts to avoid Slowloris attacks.
		WriteTimeout: time.Second * 15,
		ReadTimeout:  time.Second * 15,
		IdleTimeout:  time.Second * 60,
		Handler:      router, // Pass our instance of gorilla/mux in.
	}
	// srv.Handler = gzhttp.GzipHandler(router)
	sslKey, sslCert := "", ""
	if sslKeyI, ok := AppConfig["SslKey"]; ok {
		sslKey, sslCert = sslKeyI.(string), AppConfig["SslCert"].(string)
	}
	if sslKey == "" {
		log.Printf("Start server on port %s\n", AppConfig["Port"].(string))
		log.Fatal(srv.ListenAndServe())
	} else {
		if sslKey == "auto" {
			client := &acme.Client{DirectoryURL: autocert.DefaultACMEDirectory}
			// client := &acme.Client{DirectoryURL: "https://acme-staging-v02.api.letsencrypt.org/directory" }
			certManager := autocert.Manager{
				Prompt:     autocert.AcceptTOS,
				Cache:      autocert.DirCache("certs"),
				HostPolicy: autocert.HostWhitelist(AppConfig["Serverdomain"].(string)),
				Client:     client,
			}
			srv.TLSConfig = &tls.Config{
				GetCertificate: certManager.GetCertificate,
			}
			go http.ListenAndServe(":80", certManager.HTTPHandler(nil))
			log.Printf("Start SSL/TLS server with letsencrypt enabled on port %s\n", AppConfig["Port"].(string))
			log.Fatal(srv.ListenAndServeTLS("", ""))
		} else {
			log.Printf("Start SSL/TLS server on port %s\n", AppConfig["Port"].(string))
			log.Fatal(srv.ListenAndServeTLS(sslCert, sslKey))
		}
	}
}
func StartWebGUI() {
	SessionKey, SessionName = AppConfig["SessionKey"].(string), "golanggitlab-auth"
	SessionStore = sessions.NewCookieStore([]byte(SessionKey))
	RunScheduleTasks()
	HandleRequests()
}
func isAuthorized(endpoint func(http.ResponseWriter, *http.Request)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokens := r.Header["X-Authorization-Token"]
		session, _ := SessionStore.Get(r, SessionName)
		if len(tokens) > 0 && tokens[0] == session.Values["token"] {
			endpoint(w, r)
		} else {
			fmt.Fprintf(w, `{"error":"isAuthorized","message":"Not Authorized"}`)
		}
	})
}

//This func is used to load the home page and generate tempo token for the ajax post
func BasicAuth(handlerFunc http.HandlerFunc, username, password, realm string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		userPtn := regexp.MustCompile(`[^\s]+@[^\s]+`)
		if !userPtn.MatchString(user) {
			w.Header().Set("WWW-Authenticate", `Basic realm="`+realm+`"`)
			w.WriteHeader(401)
			w.Write([]byte("Wrong user name format.\n"))
			return
		}
		if !ok || subtle.ConstantTimeCompare([]byte(pass), []byte(password)) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="`+realm+`"`)
			w.WriteHeader(401)
			w.Write([]byte("Unauthorised.\n"))
			return
		}
		//This is used in Ajax Post auth header. See func isAuthorized
		tempToken := u.GenRandomString(32)
		// ioutil.WriteFile("/tmp/" + fmt.Sprintf("%x", userHash), []byte(tempToken), 0750)
		session, _ := SessionStore.Get(r, SessionName)
		session.Options = &sessions.Options{
			// Path:     "/",
			MaxAge:   3600,
			HttpOnly: true,
		}
		session.Values["user"] = user
		session.Values["token"] = tempToken
		u.CheckErr(session.Save(r, w), "BasicAuth session.Save")
		handlerFunc(w, r)
	}
}

//The http.Handler wrapper technique. I feel awkward but not yet having time to reduce duplicate code here
//Maybe should get the user and password, realm via session or database instead.
func BasicAuthHandler(handler http.Handler, username, password, realm string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		userPtn := regexp.MustCompile(`[^\s]+@[^\s]+`)
		if !userPtn.MatchString(user) {
			w.Header().Set("WWW-Authenticate", `Basic realm="`+realm+`"`)
			w.WriteHeader(401)
			w.Write([]byte("Wrong user name format.\n"))
			return
		}
		if !ok || subtle.ConstantTimeCompare([]byte(pass), []byte(password)) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="`+realm+`"`)
			w.WriteHeader(401)
			w.Write([]byte("Unauthorised.\n"))
			return
		}
		//This is used in Ajax Post auth header. See func isAuthorized
		tempToken := u.GenRandomString(32)
		// ioutil.WriteFile("/tmp/" + fmt.Sprintf("%x", userHash), []byte(tempToken), 0750)
		session, _ := SessionStore.Get(r, SessionName)
		session.Options = &sessions.Options{
			// Path:     "/",
			MaxAge:   3600,
			HttpOnly: true,
		}
		session.Values["user"] = user
		session.Values["token"] = tempToken
		u.CheckErr(session.Save(r, w), "BasicAuth session.Save")
		handler.ServeHTTP(w, r)
	})
}
func RunScheduleTasks() {
	ctab := crontab.New() // create cron table
	// AddJob and test the errors
	if err := ctab.AddJob("1 0 * * *", CronUpdateAllWrapper); err != nil {
		log.Printf("[WARN] - Can not add maintanance job - %v\n", err)
	}
}
func CronUpdateAllWrapper() {
	func_name := "update-all"
	lockFileName := fmt.Sprintf("/tmp/%s.lock", func_name)
	if ok, err := u.FileExists(lockFileName); ok && (err == nil) {
		return
	}
	_, err := os.Create(lockFileName)
	u.CheckErr(err, "UpdateAllWrapper create clock file")
	logFile := "RunFunction-" + func_name + "-" + "cron-user" + "-" + time.Now().Format(u.CleanStringDateLayout) + ".txt"
	f, err := os.OpenFile("log/"+logFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	u.CheckErr(err, "OpenFile Log")
	log.SetOutput(f)
	defer f.Close()
	defer log.SetOutput(os.Stdout)
	UpdateAllWrapper(GetGitlabClient(), "")
	os.Remove(lockFileName)
}
func DatabaseMaintenance() {
	conn := GetDBConn()
	defer conn.Close()
	start, _ := u.ParseTimeRange(AppConfig["LogRetention"].(string), "")
	_startTime := start.Format("2006-01-02 15:04:05.999")
	_, err := conn.Exec(fmt.Sprintf(
		`DELETE FROM log WHERE ts < "%s";
	`, _startTime))
	u.CheckErrNonFatal(err, "DatabaseMaintenance can not delete old data")
}
