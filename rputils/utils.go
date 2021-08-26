package rputils

import (
	"io"

	"html/template"

	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/cookiejar"
	"os"
	"regexp"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"
	u "github.com/sunshine69/golang-tools/utils"
	jsoniter "github.com/json-iterator/go"
	"gopkg.in/yaml.v2"
)

var (
	REPORTPORTAL_URL, rpAccessToken string
	json = jsoniter.ConfigCompatibleWithStandardLibrary
)

//Check the response for error symptom and dump it
func CheckRPApiError(m map[string]interface{}, location string) bool {
	errorCode, isError := m["errorCode"]
	if isError {
		log.Printf("[ERROR] API at %s - Code: %v - Message: %s\n", location, errorCode, m["message"])
		return false
	}
	return true
}
func Get_rp_project(project_name, api_tok string, jar *cookiejar.Jar) map[string]interface{} {
	return u.MakeRequest("GET", map[string]interface{}{
		"token": "Bearer " + api_tok,
		"headers": map[string]string{
			"Content-Type": "application/json",
		},
		"url": fmt.Sprintf("%s/api/v1/project/%s", REPORTPORTAL_URL, project_name),
	}, []byte(""), jar)
}
func Create_rp_project(project_name, api_tok string, jar *cookiejar.Jar) bool {
	data := map[string]string{
		"projectName": project_name,
		"entryType":   "INTERNAL",
	}
	_data, _ := json.Marshal(data)
	m := u.MakeRequest("POST", map[string]interface{}{
		"token": "Bearer " + api_tok,
		"headers": map[string]string{
			"Content-Type": "application/json",
		},
		"url": fmt.Sprintf("%s/api/v1/project", REPORTPORTAL_URL),
	}, _data, jar)
	fmt.Printf("create_rp_project %v\n", m)
	return true
}

func Delete_rp_projects(projectIDList []int, api_tok string, jar *cookiejar.Jar) bool {
	data := map[string][]int{
		"ids": projectIDList,
	}
	_data, _ := json.Marshal(data)
	m := u.MakeRequest("DELETE", map[string]interface{}{
		"token": "Bearer " + api_tok,
		"headers": map[string]string{
			"Content-Type": "application/json",
		},
		"url": fmt.Sprintf("%s/api/v1/project", REPORTPORTAL_URL),
	}, _data, jar)
	fmt.Printf("Delete_rp_projects %v\n", m)
	return true
}

func Get_all_rp_project(ui_token string, jar *cookiejar.Jar) map[string]interface{} {
	return u.MakeRequest("GET", map[string]interface{}{
		"token": "Bearer " + ui_token,
		"url":   fmt.Sprintf("%s/api/v1/project/list?page.size=10000", REPORTPORTAL_URL),
	}, []byte(""), jar)
}

// def create_rp_user():
//     pass

func Assign_user_project(project_name, api_token, user_name, user_role string, jar *cookiejar.Jar) {
	if user_role == "" {
		user_role = "PROJECT_MANAGER"
	}
	_data := map[string]interface{}{
		"userNames": map[string]string{
			user_name: user_role,
		},
	}
	data, _ := json.Marshal(_data)
	m := u.MakeRequest("PUT", map[string]interface{}{
		"token": "Bearer " + api_token,
		"url":   fmt.Sprintf("%s/api/v1/project/%s/assign", REPORTPORTAL_URL, project_name),
		"headers": map[string]string{
			"Content-Type": "application/json",
		},
	}, data, jar)
	fmt.Println(m)
}

func Get_ui_token(username, password string, jar *cookiejar.Jar) string {
	data := []byte(fmt.Sprintf("username=%s&password=%s&grant_type=password", username, password))
	req, _ := http.NewRequest("POST", fmt.Sprintf("%s/uat/sso/oauth/token", REPORTPORTAL_URL), bytes.NewBuffer(data))
	client := http.Client{
		Jar:     jar,
		Timeout: 20 * time.Second,
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("ui", "uiman")
	resp, err := client.Do(req)
	u.CheckErr(err, "Get_ui_token client.Do")
	defer resp.Body.Close()
	content, err := ioutil.ReadAll(resp.Body)
	u.CheckErr(err, "Get_ui_token read body")
	m := map[string]interface{}{}
	u.CheckErr(json.Unmarshal(content, &m), "Get_ui_token Unmarshal")
	if token, ok := m["access_token"]; ok {
		return token.(string)
	} else {
		fmt.Printf("ERROR token not found %v\n", string(content))
	}
	return ""
}

func Get_api_token(username, password, ui_token string, jar *cookiejar.Jar) string {
	if ui_token == "" {
		ui_token = Get_ui_token(username, password, jar)
		fmt.Printf("ui token: %s\n", ui_token)
	}
	m := u.MakeRequest("GET", map[string]interface{}{"token": "Bearer " + ui_token}, []byte(""), jar)
	token := m["access_token"]
	if token == nil {
		m := u.MakeRequest("POST", map[string]interface{}{"token": "Bearer " + ui_token}, []byte(""), jar)
		if token, ok := m["access_token"]; ok {
			return token.(string)
		} else {
			log.Fatalf("Can not get token - %v\n", m)
		}
	}
	return token.(string)
}

func TagsConversion(tags string) []interface{} {
	_tags := strings.Split(tags, ",")
	listAttr := make([]interface{}, 0)
	for _, _tag := range _tags {
		if _tag != "" {
			attribute := map[string]interface{}{
				"value": _tag,
				"key":   nil,
			}
			listAttr = append(listAttr, attribute)
		}
	}
	return listAttr
}
func GetLaunch(api_tok, projectName string, launchIDGen interface{}, jar *cookiejar.Jar) map[string]interface{} {
	url := ""
	launchUUID, ok := launchIDGen.(string)
	if ok {
		url = fmt.Sprintf("%s/api/v1/%s/launch/uuid/%s", REPORTPORTAL_URL, projectName, launchUUID)
	} else {
		launchID, ok := launchIDGen.(int)
		if !ok {
			log.Printf("[ERROR] GetLaunch launchIDGen must be a string or int\n")
			return map[string]interface{}{}
		}
		url = fmt.Sprintf("%s/api/v1/%s/launch/%d", REPORTPORTAL_URL, projectName, launchID)
	}
	m := u.MakeRequest("GET", map[string]interface{}{
		"token": "Bearer " + api_tok,
		"headers": map[string]string{
			"Content-Type": "application/json",
		},
		"url": url,
	}, []byte(""), jar)
	return m
}

//Update a launch. Noted that the tags format is a coma separated string, and it is merged/relace with current tags depending on the value of tags_update_ops (add|delete|replace) (add new tag to existing tag, delete a tag in the existing tag, and replace the whole existing tags with current one)
func UpdateLaunch(api_tok, projectName string, launchIDGen interface{}, description, tags, tags_update_ops string, jar *cookiejar.Jar) string {
	if api_tok == "" {
		ui_tok := Get_ui_token(os.Getenv("REPORTPORTAL_ADMIN_USER"), os.Getenv("REPORTPORTAL_ADMIN_PASS"), jar)
		api_tok = Get_api_token(os.Getenv("REPORTPORTAL_ADMIN_USER"), os.Getenv("REPORTPORTAL_ADMIN_PASS"), ui_tok, jar)
	}
	launchID := -1
	curLaunch := GetLaunch(api_tok, projectName, launchIDGen, jar)
	if _launchID, ok := curLaunch["id"].(float64); ok {
		launchID = int(_launchID)
	} else {
		log.Printf("[ERROR] UpdateLaunch not find launch id - %v\n", curLaunch)
		return ""
	}
	curAttributes := curLaunch["attributes"].([]interface{})
	inputAttributes := TagsConversion(tags)
	var newAttributes []interface{}
	switch tags_update_ops {
	case "add", "del":
		newAttributes = u.MergeAttributes(inputAttributes, curAttributes, tags_update_ops)
	default:
		newAttributes = inputAttributes
	}
	_data := map[string]interface{}{
		"attributes":  newAttributes,
		"description": description,
		"mode":        "DEFAULT",
	}
	data, _ := json.Marshal(_data)
	m := u.MakeRequest("PUT", map[string]interface{}{
		"token": "Bearer " + api_tok,
		"headers": map[string]string{
			"Content-Type": "application/json",
		},
		"url": fmt.Sprintf("%s/api/v1/%s/launch/%d/update", REPORTPORTAL_URL, projectName, launchID),
	}, data, jar)
	if CheckRPApiError(m, fmt.Sprintf("UpdateLaunch tags: %s - ops: %s - newAttributes: %v", tags, tags_update_ops, newAttributes)) {
		return m["message"].(string)
	}
	return ""
}

// return ItemID
func StartRPItem(api_tok, projectName, name, launchUUID, parentItemUUID, itemType, description, tags string, jar *cookiejar.Jar) string {
	if itemType == "" {
		itemType = "step"
	}
	_data := map[string]interface{}{
		"name":        name,
		"attributes":  TagsConversion(tags),
		"startTime":   time.Now().Format(time.RFC3339),
		"type":        itemType,
		"launchUuid":  launchUUID,
		"description": description,
	}
	data, _ := json.Marshal(_data)
	url := ""
	if parentItemUUID == "" {
		url = fmt.Sprintf("%s/api/v1/%s/item", REPORTPORTAL_URL, projectName)
	} else {
		url = fmt.Sprintf("%s/api/v1/%s/item/%s", REPORTPORTAL_URL, projectName, parentItemUUID)
	}
	m := u.MakeRequest("POST", map[string]interface{}{
		"token": "Bearer " + api_tok,
		"headers": map[string]string{
			"Content-Type": "application/json",
		},
		"url": url,
	}, data, jar)
	if CheckRPApiError(m, fmt.Sprintf("StartRPItem launchUUID %s type %s", launchUUID, itemType)) {
		return m["id"].(string)
	}
	return "-1"
}

func StartRPRootItem(api_tok, projectName, name, launchUUID, description, tags string, jar *cookiejar.Jar) string {
	return StartRPItem(api_tok, projectName, name, launchUUID, "", "SUITE", description, tags, jar)
}

//Start a new launch with description and list of tags.
//Return the string "launchUUID=%s\nrootItemUUID=%s"
func LaunchTestRun(api_tok, projectName, name, description, tags, mode string, createRootItem bool, jar *cookiejar.Jar) string {
	if mode == "" {
		mode = "DEFAULT"
	}
	_data := map[string]interface{}{
		"attributes":  TagsConversion(tags),
		"description": description,
		"mode":        mode,
		"name":        name,
		"startTime":   time.Now().Format(time.RFC3339),
	}
	data, _ := json.Marshal(_data)

	m := u.MakeRequest("POST", map[string]interface{}{
		"token": "Bearer " + api_tok,
		"headers": map[string]string{
			"Content-Type": "application/json",
		},
		"url": fmt.Sprintf("%s/api/v1/%s/launch", REPORTPORTAL_URL, projectName),
	}, data, jar)
	launchUUID := "-1" //This is not launchID as interger. Bunch of API call using this but not the other vice verser. We probably need to call GET launch info to find the interger ID. <yuk>
	output := ""
	if CheckRPApiError(m, fmt.Sprintf("LaunchTestRun tags %s", tags)) {
		launchUUID = m["id"].(string)
		if createRootItem {
			rootItemID := StartRPRootItem(api_tok, projectName, name, launchUUID, description, "", jar)
			output = fmt.Sprintf("launchUUID=%s\nrootItemUUID=%s", launchUUID, rootItemID)
		} else {
			output = fmt.Sprintf("launchUUID=%s\nrootItemUUID=-1", launchUUID)
		}
	}
	return output
}

func GetLaunchID(api_tok, projectName, launchUUID string, jar *cookiejar.Jar) int64 {
	var launchID int64 = -1

	m := u.MakeRequest("GET", map[string]interface{}{
		"token": "Bearer " + api_tok,
		"headers": map[string]string{
			"Content-Type": "application/json",
		},
		"url": fmt.Sprintf("%s/api/v1/%s/launch/uuid/%s", REPORTPORTAL_URL, projectName, launchUUID),
	}, []byte(""), jar)
	if CheckRPApiError(m, fmt.Sprintf("GetLaunchID by UUID %s", launchUUID)) {
		launchID = int64(m["id"].(float64))
	}
	return launchID
}
func GetLaunchURL(api_tok, projectName, launchUUID string, jar *cookiejar.Jar) string {
	id := GetLaunchID(api_tok, projectName, launchUUID, jar)
	return fmt.Sprintf("%s/ui/#%s/launches/all/%d", REPORTPORTAL_URL, projectName, id)
}
func SaveRPLog(api_tok, projectName, launchUUID, itemUUID, message string, jar *cookiejar.Jar) string {
	_data := map[string]interface{}{
		// "file": {
		// 	"name": "string"
		//   },
		"itemUuid":   itemUUID,
		"launchUuid": launchUUID,
		"level":      "error",
		"message":    message,
		"time":       time.Now().Format(time.RFC3339),
	}
	data, _ := json.Marshal(_data)

	m := u.MakeRequest("POST", map[string]interface{}{
		"token": "Bearer " + api_tok,
		"headers": map[string]string{
			"Content-Type": "application/json",
		},
		"url": fmt.Sprintf("%s/api/v1/%s/log", REPORTPORTAL_URL, projectName),
	}, data, jar)
	if CheckRPApiError(m, fmt.Sprintf("SaveRPLog launchUUID %s itemUUID %s", launchUUID, itemUUID)) {
		return m["id"].(string)
	}
	return "-1"
}

func AttachFileToRPItem(api_tok, projectName, launchUUID, itemUUID, filePath string) error {
	/* Not work, RP bug? It always complain about missing the field json_request_part but it is there...
	 */
	jsonPaths := fmt.Sprintf(`[
			{
				"launchUuid": "%s",
				"itemUuid": "%s",
				"time": "%d",
				"message": "Log message",
				"level": "ERROR",
				"file": {
					"name": "%s"
				}
			}
		]`, launchUUID, itemUUID, time.Now().UnixNano()/int64(time.Millisecond), filePath)

	tempFile, err := ioutil.TempFile("", "jsonPaths.json")
	defer os.Remove(tempFile.Name())

	u.CheckErr(err, "json_request_part/tempfile")
	_, err = tempFile.Write([]byte(jsonPaths))
	u.CheckErr(err, "json_request_part/tempfile write")

	client := &http.Client{
		Timeout: time.Second * 10,
	}
	values := map[string]io.Reader{
		"file":              u.MustOpenFile(filePath),
		"json_request_part": u.MustOpenFile(tempFile.Name()),
	}
	url := fmt.Sprintf("%s/api/v1/%s/log", REPORTPORTAL_URL, projectName)
	err = u.Upload(client, url, values, map[string]string{
		filePath:        "text/plain",
		tempFile.Name(): "application/json",
	}, map[string]string{
		"Authorization": fmt.Sprintf("bearer %s", api_tok),
	})
	return u.CheckErrNonFatal(err, "AttachFileToRPItem")
}

func StopRPItem(api_tok, projectName, launchUUID, itemUUID, status, message string, jar *cookiejar.Jar) {
	_data := map[string]interface{}{
		"status":     status,
		"endTime":    time.Now().Format(time.RFC3339),
		"launchUuid": launchUUID,
		"issue": map[string]interface{}{
			"issueType": "pb001",
			"comment":   message,
		},
	}
	data, _ := json.Marshal(_data)

	m := u.MakeRequest("PUT", map[string]interface{}{
		"token": "Bearer " + api_tok,
		"headers": map[string]string{
			"Content-Type": "application/json",
		},
		"url": fmt.Sprintf("%s/api/v1/%s/item/%s", REPORTPORTAL_URL, projectName, itemUUID),
	}, data, jar)
	if CheckRPApiError(m, fmt.Sprintf("StopRPItem launchUUID %s itemUUID %s", launchUUID, itemUUID)) {
		fmt.Printf("OK Stopped Item %s\n", itemUUID)
	}
}

func StopLaunchTestRun(api_tok, projectName, launchID, itemID, status, message, tags string, jar *cookiejar.Jar) string {
	if itemID != "" {
		StopRPItem(api_tok, projectName, launchID, itemID, status, message, jar)
	}
	_data := map[string]interface{}{
		"attributes": TagsConversion(tags),
		"status":     status,
		"endTime":    time.Now().Format(time.RFC3339),
	}
	data, _ := json.Marshal(_data)

	m := u.MakeRequest("PUT", map[string]interface{}{
		"token": "Bearer " + api_tok,
		"headers": map[string]string{
			"Content-Type": "application/json",
		},
		"url": fmt.Sprintf("%s/api/v1/%s/launch/%s/finish", REPORTPORTAL_URL, projectName, launchID),
	}, data, jar)
	if CheckRPApiError(m, fmt.Sprintf("StopLaunchTestRun launchID %s itemID %s", launchID, itemID)) {
		return fmt.Sprintf("OK launch %s is finished with reported status %s\n", launchID, status)
	} else {
		return "-1"
	}
}

func Generate_service_name(srv_name string) string {
	//reportportal has some rules so we need this thing
	output := ""
	mangle_names := map[string]string{
		// Not sure why but project name created with the `user` string it caused errors (java exception)
		"user": "user_service",
	}
	if len(srv_name) < 3 {
		output = fmt.Sprintf("%s_service", srv_name)
	} else {
		output = srv_name
	}
	if output1, ok := mangle_names[output]; ok {
		return output1
	} else {
		return output
	}
}

func ProcessYamlFile(filePath string) string {
	log.Printf("Process file %s", filePath)
	inputDataByte, err := ioutil.ReadFile(filePath)
	u.CheckErr((err), "processYamlFile 1")
	m := make(map[interface{}]interface{})
	err = yaml.Unmarshal([]byte(inputDataByte), &m)
	u.CheckErr(err, "processYamlFile 2")
	m1 := m["extensions"].(map[interface{}]interface{})
	m2 := m1["enabled"].([]interface{})
	for _idx, _item := range m2 {
		if item, ok := _item.(map[interface{}]interface{}); ok {
			// fmt.Printf("DEBUG: %v\n", item)
			if _, ok := item["ReportingPortalAgent"]; ok {
				// fmt.Printf("Remove %v,\n", _testkey)
				m2 = u.RemoveItem(m2, _idx)
			}
		}
	}
	//Insert ours
	// _serviceName := filepath.Base(filePath)
	// serviceName := strings.Split(_serviceName, ".")[0]
	// serviceName = generate_service_name(serviceName)
	// nodeItem := make(map[string]map[string]string)
	// nodeItem["ReportingPortalAgent"] = map[string]string{
	// 	"UUID":              "318bc2d5-9479-40ca-807f-f9d7fb04463e",
	// 	"host":              REPORTPORTAL_URL,
	// 	"launchDescription": fmt.Sprintf("Service %s", serviceName),
	// 	"launchName":        serviceName,
	// 	"projectName":       serviceName,
	// 	"timeZone":          ".000+00:00",
	// }
	// fmt.Printf("%v\n", nodeItem)
	// m2 = append(m2, nodeItem)
	m1["enabled"] = m2
	m["extensions"] = m1
	marshallBack, err := yaml.Marshal(&m)
	u.CheckErr(err, "processYamlFile marshallBack")
	ioutil.WriteFile(filePath, []byte(marshallBack), 0755)
	// return serviceName
	return "OK"
}

func GetLaunchByTags(api_tok, projectName, tags string, jar *cookiejar.Jar) map[string]interface{} {
	m := u.MakeRequest("GET", map[string]interface{}{
		"token": "Bearer " + api_tok,
		"headers": map[string]string{
			"Content-Type": "application/json",
		},
		"url": fmt.Sprintf("%s/api/v1/%s/launch/?filter.has.attributeValue=%s&page.size=1000", REPORTPORTAL_URL, projectName, tags),
	}, []byte(""), jar)
	return m
}

type ErrorReport struct {
	Title       string
	LaunchCount int
	ErrorCount  int
	Errors      []map[string]string
}

func GetErrorReportByTag(rpAccessToken, projectName, tags string, jar *cookiejar.Jar) ErrorReport {
	if jar == nil {
		jar, _ = cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	}
	errorReport := ErrorReport{
		Title:       projectName,
		LaunchCount: 0,
		ErrorCount:  0,
	}
	errorReport.Title = "Errors list for launches match tags " + tags

	launchesOuput := GetLaunchByTags(rpAccessToken, projectName, tags, jar)
	if u.Getenv("DEBUG", "0") == "1" {
		fmt.Printf("%s\n", u.JsonDump(launchesOuput, "    "))
	}
	launches := launchesOuput["content"].([]interface{})

	for _, launchI := range launches {
		launch := launchI.(map[string]interface{})
		status := launch["status"].(string)
		failcountI, failcount := launch["statistics"].(map[string]interface{})["executions"].(map[string]interface{})["failed"], 0.0
		if failcountI != nil {
			failcount = failcountI.(float64)
		}
		if status == "FAILED" || failcount > 0 {
			errorLaunch := map[string]string{
				"description": launch["description"].(string),
				"status":      status,
			}
			errorReport.Errors = append(errorReport.Errors, errorLaunch)
			errorReport.ErrorCount++
		}
	}
	errorReport.LaunchCount = len(launches)
	return errorReport
}

func MakeRPDescription(templateData map[string]interface{}) string {
	_launchDescriptionTemplate := `PIPELINE <a href='{{.project_url}}/-/pipelines/{{.pipeline_id}}'>{{.pipeline_id}}</a> JOB <a href='{{.ci_job_url}}'>{{.ci_job_id}}</a> COMMIT <a href='{{.commit_url}}'>{{.ci_commit_short_sha}}</a>
{{- if .downstream -}}
Downstream: {{- range .downstream -}}
<a href='{{.web_url}}'>{{.id}}</a>
{{- end -}}
{{- end -}}
{{- if .username }}
User <img src='{{.avatar_url}}' style="width:20px;height:20px;"><a href='{{.user_url}}'>{{.username}}</a> {{ .email }}
{{- end -}}
`
	if _t, err := template.New("desc").Parse(_launchDescriptionTemplate); err == nil {
		buff := &strings.Builder{}
		u.CheckErr(_t.Execute(buff, templateData), "TEMPLATE DESCRIPTION")
		return buff.String()
	} else {
		log.Printf("[ERROR] templating description field %v", err)
		return ""
	}
}

//See codeception .gitlab-ci.yaml for more infor about the usage and input. The logfileObj is the obj parsed from the logfile field in the curl call.
func CheckAndMakeRPLaunch(rpProjectName string, logfileObj map[string]interface{}, application, message string) bool {
	applicationObj := make(map[string]interface{})
	err := json.UnmarshalFromString(application, &applicationObj)
	if u.CheckErrNonFatal(err, "UnmarshalFromString application") != nil {
		return false
	}
	jid := int(applicationObj["job_id"].(float64))
	pid := int(applicationObj["pipeline_id"].(float64))
	projectURL := applicationObj["project_url"].(string)
	commitSHA := applicationObj["commit_sha"].(string)
	commitURL := fmt.Sprintf("%s/-/commit/%s", projectURL, commitSHA)
	suite := applicationObj["suite"].(string)
	test_env := applicationObj["test_env"].(string)
	tags := fmt.Sprintf("JID:%d,PID:%d,%s,%s", jid, pid, suite, test_env)

	rpAccessToken = os.Getenv("RP_ACCESSTOKEN")
	REPORTPORTAL_URL = os.Getenv("REPORTPORTAL_URL")
	jar, _ := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	_launches := GetLaunchByTags(rpAccessToken, rpProjectName, fmt.Sprintf("JID:%d", jid), jar)
	launches := _launches["content"].([]interface{})

	var launchUUID, itemUUID, rpStatus, rpMessage string
	var launchID int
	isNewLaunch := false

	error_code := int(logfileObj["error_code"].(float64))
	log.Printf("[DEBUG] error_code: %d\n", error_code)
	if error_code == 0 {
		rpMessage = "OK"
		rpStatus = "PASSED"

	} else {
		rpMessage = fmt.Sprintf("[ERROR] error_code %d is not 0", error_code)
		// SaveRPLog(rpAccessToken, rpProjectName, launchUUID, itemUUID, rpMessage , jar)
		rpStatus = "FAILED"
	}

	launchCount := len(launches)
	launchDescription := ""

	if launchCount > 1 {
		log.Printf("[ERROR] launch exists more than one for tags JID:%d\n", jid)
		return false
	} else if launchCount == 0 { // create new launch
		isNewLaunch = true
		templateData := map[string]interface{}{
			"ci_job_url":          fmt.Sprintf("%s/-/jobs/%d", projectURL, jid),
			"ci_job_id":           jid,
			"pipeline_id":         pid,
			"project_url":         projectURL,
			"commit_url":          commitURL,
			"ci_commit_short_sha": commitSHA[0:8],
		}
		launchDescription = MakeRPDescription(templateData)
		log.Printf("[DEBUG] Create new launch, launchDescription %s - tags - %s\n", launchDescription, tags)
		output := LaunchTestRun(rpAccessToken, rpProjectName, "Launch", launchDescription, tags, "", true, jar)
		configObj, _ := u.ReadPropertiesString(output)
		launchUUID, itemUUID = configObj["launchUUID"], configObj["rootItemUUID"]
		SaveRPLog(rpAccessToken, rpProjectName, launchUUID, itemUUID, rpMessage, jar)
	} else if launchCount == 1 {
		_launch := launches[0].(map[string]interface{})
		launchUUID = _launch["uuid"].(string)
	}
	if isNewLaunch {
		StopLaunchTestRun(rpAccessToken, rpProjectName, launchUUID, itemUUID, rpStatus, message, "fixture-crash", jar)
		// refresh the launches so that we can use in the next code
		_launches = GetLaunchByTags(rpAccessToken, rpProjectName, fmt.Sprintf("JID:%d", jid), jar)
		launches = _launches["content"].([]interface{})
	}
	for _, _item := range launches {
		launchID = int(_item.(map[string]interface{})["id"].(float64))
	}
	// buildLogItemUUID := StartRPItem(rpAccessToken, rpProjectName, "build_log", launchUUID, "test", jar)
	// tmpfile, err := ioutil.TempFile("", "error.log")
	// u.CheckErr(err, "ioutil.TempFile")
	// defer os.Remove(tmpfile.Name()) // clean up
	// if _, err := tmpfile.Write([]byte(message)); err != nil {
	// 	log.Fatal(err)
	// }
	// if AttachFileToRPItem(rpAccessToken, rpProjectName, launchUUID, buildLogItemUUID, tmpfile.Name() ) == nil {
	// 	log.Printf("[INFO] AttachFileToRPItem OK rpProjectName %s - launchUUID %s - buildLogItemUUID %s", rpProjectName, launchUUID, buildLogItemUUID)
	// }
	// StopRPItem(rpAccessToken, rpProjectName, launchUUID, buildLogItemUUID, rpStatus, "", jar )
	//Automate test items update
	//Update the items of the launch with proper defect type
	log.Printf("[INFO] Going to run UpdateLaunchItemsWithDefectType with rpStatus %s launchID %d\n", rpStatus, launchID)
	UpdateLaunchItemsWithDefectType(rpAccessToken, rpProjectName, launchID, "FAILED", rpStatus, message, launchDescription, jar)
	return true
}

//Return a locator - will be used in UpdateLaunchItemsWithDefectType
//The subTypeLongName is the one we created using the webgui
func GetProjectSubTypeID(rpAccessToken, rpProjectName, subTypeLongName string, jar *cookiejar.Jar) string {
	url := fmt.Sprintf("%s/api/v1/%s/settings", REPORTPORTAL_URL, rpProjectName)
	m := u.MakeRequest("GET", map[string]interface{}{
		"token": "Bearer " + rpAccessToken,
		"headers": map[string]string{
			"Content-Type": "application/json",
		},
		"url": url,
	}, []byte(""), jar)
	subTypes := m["subTypes"].(map[string]interface{})
	for _, val := range subTypes {
		_val := val.([]interface{})
		for _, val1 := range _val {
			_val1 := val1.(map[string]interface{})
			for key, val2 := range _val1 {
				if key == "longName" {
					_val2 := val2.(string)
					if _val2 == subTypeLongName {
						return _val1["locator"].(string)
					}
				}
			}
		}
	}
	return ""
}

//Classified item typed for a launch. Get all items qualified for the filter_status, set the issueType based on a filter_status and set_status
// data is provided as a more facts to help making decision to assign issueType. Usually it is the raw log output of the test command. Not in use yet though.
func UpdateLaunchItemsWithDefectType(rpAccessToken, rpProjectName string, launchID int, filter_status, set_status, data, description string, jar *cookiejar.Jar) []map[string]interface{} {
	issueType := ""
	url := fmt.Sprintf("%s/api/v1/%s/item?filter.eq.status=%s&filter.eq.launchId=%d", REPORTPORTAL_URL, rpProjectName, filter_status, launchID)
	m := u.MakeRequest("GET", map[string]interface{}{
		"token": "Bearer " + rpAccessToken,
		"headers": map[string]string{
			"Content-Type": "application/json",
		},
		"url": url,
	}, []byte(""), jar)

	var respList []map[string]interface{}
	itemList, ok := m["content"].([]interface{})
	if !ok {
		log.Printf("[ERROR] UpdateLaunchItemsWithDefectType Can not get launch %d item with this filter %s - %v\n", launchID, filter_status, m)
		return []map[string]interface{}{}
	}
	log.Printf("[DEBUG] url: '%s' - Get Item List: %v\n", url, itemList)
	for _, item := range itemList {
		//Find the issueType depends on the filter_status and the set_status
		if filter_status == "FAILED" {
			switch set_status {
			case "PASSED":
				issueType = GetProjectSubTypeID(rpAccessToken, rpProjectName, "Latency Fail", jar) // issues type. Not really an issues at all
			case "FAILED":
				if strings.Contains(data, "APIFixturesLoader.php") &&
					strings.Contains(data, "Failed to load fixture") &&
					strings.Contains(data, "COMMAND DID NOT FINISH PROPERLY") {
					issueType = GetProjectSubTypeID(rpAccessToken, rpProjectName, "Api Fixture Bug", jar)
				} else {
					issueType = "ti001" // To investigate we are not sure what it is
				}
			}
		}
		post_data := fmt.Sprintf(`{
			"issues": [
			  {
				"issue": {
				  "autoAnalyzed": false,
				  "comment": "%s",
				  "externalSystemIssues": [
				  ],
				  "ignoreAnalyzer": false,
				  "issueType": "%s"
				},
				"testItemId": %d
			  }
			]
		}`, "failed", issueType, int(item.(map[string]interface{})["id"].(float64)))
		log.Printf("[DEBUG] update item data %s\n", post_data)
		m = u.MakeRequest("PUT", map[string]interface{}{
			"token": "Bearer " + rpAccessToken,
			"headers": map[string]string{
				"Content-Type": "application/json",
			},
			"url": fmt.Sprintf("%s/api/v1/%s/item", REPORTPORTAL_URL, rpProjectName),
		}, []byte(post_data), jar)
		log.Printf("[DEBUG] RP return %s\n", u.JsonDump(m, "    "))
		respList = append(respList, m)
	}
	//Base on the data update tags for the launch if needed
	//Parse this `POST https://api-dev.go1.co/onboard2/portal?x-expensive=1 find out the service name and tag it
	//EP:onboard2/portal for example. Also update description having POST <URL> <OUTPUT STR>

	tags := ""
	newDescription := ""
	findBrokenServiceForFixturePtn := regexp.MustCompile("[`]*(POST|GET) http[s]*://[^/\\s]+/([^?]+)[`]*")
	matches := findBrokenServiceForFixturePtn.FindStringSubmatch(data)
	if len(matches) == 3 {
		tags = fmt.Sprintf("EP:%s", matches[2])
		m1 := regexp.MustCompile("`([\\d]{3,3} [^`]+)`").FindStringSubmatch(data)
		if len(m1) == 2 {
			newDescription = fmt.Sprintf("%s\n%s %s", description, matches[0], m1[1])
		} else {
			newDescription = fmt.Sprintf("%s\n%s", description, matches[0])
		}
		log.Printf("[DEBUG] start auto UpdateLaunch ID: %d - description %s - tags %s ", launchID, newDescription, tags)
		o := UpdateLaunch(rpAccessToken, rpProjectName, launchID, newDescription, tags, "add", jar)
		log.Printf("[DEBUG]: UpdateLaunch return %s\n", o)
	} else {
		log.Printf("[DEBUG] findBrokenServiceForFixturePtn not match anything. data: " + data)
	}
	return respList
}
