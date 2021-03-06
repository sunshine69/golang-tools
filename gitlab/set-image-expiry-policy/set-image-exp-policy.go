package main

import (
	"strconv"
	"flag"
	"fmt"
	u "localhost.com/utils"
	"github.com/xanzy/go-gitlab"
	"io/ioutil"
	"log"
	"os"
	"time"
)

var (
	GitLabToken, projectSearchStr, configFile, logDir string
)

func ParseConfig() map[string]interface{} {
	if configFile == "" {
		log.Fatalf("Config file required. Run with -h for help")
	}
	config := u.ParseConfig(configFile)
	if projectSearchStr == "" && config["projectSearchStr"].(string) != "" {
		projectSearchStr = config["projectSearchStr"].(string)
	}
	return config
}

func main() {
	flag.StringVar(&projectSearchStr, "project-search-string", "", "Project search Str. Empty means everything. If it is a integer then we use as project ID and search for it")
	flag.StringVar(&projectSearchStr, "s", "", "Project search Str. Empty means everything")
	flag.StringVar(&configFile, "f", "", `Config file. A json file in the format
	{
		"gitlabAPIBaseURL": "https://code.go1.com.au/api/v4",
		"gitlabToken": "changeme",
		"projectSearchStr": "",
		"Cadence": "7d",
		"Enabled": true,
		"NameRegexDelete": ".*",
		"NameRegexKeep": "",
		"KeepN": 100,
		"OlderThan": "90d"
	}`)
	flag.StringVar(&GitLabToken, "tok", "", "GitLabToken if empty then read from env var GITLAB_TOKEN")
	flag.StringVar(&logDir, "logdir", os.Getenv("HOME"), "Log directory")
	flag.Parse()

	config := ParseConfig()
	u.ConfigureLogging(os.Stdout)

	if GitLabToken = u.Getenv("GITLAB_TOKEN", "-1"); GitLabToken == "-1" {
		if GitLabToken = config["gitlabToken"].(string); GitLabToken == "changeme" || GitLabToken == "" {
			log.Fatalf("Requires env var GITLAB_TOKEN")
		}
	}
	git, err := gitlab.NewClient(GitLabToken, gitlab.WithBaseURL(config["gitlabAPIBaseURL"].(string)))
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	opt := &gitlab.ListProjectsOptions{
		Search: gitlab.String(projectSearchStr),
		ListOptions: gitlab.ListOptions{
			PerPage: 25,
			Page:    1,
		},
	}
	Cadence := config["Cadence"].(string)
	Enabled := config["Enabled"].(bool)
	NameRegexDelete := config["NameRegexDelete"].(string)
	NameRegexKeep := config["NameRegexKeep"].(string)
	KeepN := int(config["KeepN"].(float64))
	OlderThan := config["OlderThan"].(string)

	containerExpirationPolicyAttributes := gitlab.ContainerExpirationPolicyAttributes{
		Cadence:         &Cadence,
		Enabled:         &Enabled,
		NameRegexDelete: &NameRegexDelete,
		NameRegexKeep:   &NameRegexKeep,
		KeepN:           &KeepN,
		OlderThan:       &OlderThan,
	}
	editPrjOpt := gitlab.EditProjectOptions{
		ContainerExpirationPolicyAttributes: &containerExpirationPolicyAttributes,
	}
	output := map[string]map[string]interface{}{
		"nochange": map[string]interface{}{},
		"changed":  map[string]interface{}{},
	}
	projectService := git.Projects
	registryService := git.ContainerRegistry
	for {
		var (
			projects []*gitlab.Project
			project *gitlab.Project
			resp *gitlab.Response
			err error
		)
		projectID, err := strconv.Atoi(projectSearchStr)
		if err == nil {
			project, resp, err = projectService.GetProject(projectID, nil)
			u.CheckErr(err, "GetProject")
			projects = []*gitlab.Project{ project }
		} else {
			projects, resp, err = projectService.ListProjects(opt)
			u.CheckErr(err, "Projects.ListProjects")
		}
		for _, row := range projects {
			log.Printf("[DEBUG] %s\n", u.JsonDump(row, "    "))

			if ! row.ContainerRegistryEnabled {
				continue
			}
			registry, _, err := registryService.ListRegistryRepositories(row.ID, nil)
			u.CheckErr(err, "ListRegistryRepositories")
			if len(registry) == 0 {
			//For these project even we set enabled gitlab will reset it back to disable for a while
				continue
			}
			if Equal_ContainerExpirationPolicyAttributes(&containerExpirationPolicyAttributes, row.ContainerExpirationPolicy) {
				fmt.Printf("Project ID %d - Already equal, no action\n", row.ID)
				output["nochange"][row.WebURL] = map[string]interface{}{
					"name":              row.Name,
					"url":               row.WebURL,
					"cadence":           row.ContainerExpirationPolicy.Cadence,
					"enabled":           row.ContainerExpirationPolicy.Enabled,
					"keep_n":            row.ContainerExpirationPolicy.KeepN,
					"older_than":        row.ContainerExpirationPolicy.OlderThan,
					"name_regex_delete": row.ContainerExpirationPolicy.NameRegexDelete,
					"name_regex_keep":   row.ContainerExpirationPolicy.NameRegexKeep,
					"next_run_at":       row.ContainerExpirationPolicy.NextRunAt.Format(u.AUTimeLayout),
				}
			} else {
				fmt.Printf("Project ID %d - Action Update\n", row.ID)
				before := map[string]interface{}{
					"id":                row.ID,
					"name":              row.Name,
					"url":               row.WebURL,
					"cadence":           row.ContainerExpirationPolicy.Cadence,
					"enabled":           row.ContainerExpirationPolicy.Enabled,
					"keep_n":            row.ContainerExpirationPolicy.KeepN,
					"older_than":        row.ContainerExpirationPolicy.OlderThan,
					"name_regex_delete": row.ContainerExpirationPolicy.NameRegexDelete,
					"name_regex_keep":   row.ContainerExpirationPolicy.NameRegexKeep,
					"next_run_at":       row.ContainerExpirationPolicy.NextRunAt.Format(u.AUTimeLayout),
				}
				_, _, err := projectService.EditProject(row.ID, &editPrjOpt)
				u.CheckErr(err, "projectService.EditProject")
				fmt.Printf("Updated %d\n", row.ID)
				_prj, _, err := projectService.GetProject(row.ID, nil)
				u.CheckErr(err, "projectService.GetProject")
				// after := output["changed"].(map[string]interface{})["after"].([]map[string]interface{})
				after := map[string]interface{}{
					"id":                _prj.ID,
					"name":              _prj.Name,
					"url":               _prj.WebURL,
					"cadence":           _prj.ContainerExpirationPolicy.Cadence,
					"enabled":           _prj.ContainerExpirationPolicy.Enabled,
					"keep_n":            _prj.ContainerExpirationPolicy.KeepN,
					"older_than":        _prj.ContainerExpirationPolicy.OlderThan,
					"name_regex_delete": _prj.ContainerExpirationPolicy.NameRegexDelete,
					"name_regex_keep":   _prj.ContainerExpirationPolicy.NameRegexKeep,
					"next_run_at":       _prj.ContainerExpirationPolicy.NextRunAt.Format(u.AUTimeLayout),
				}
				output["changed"][_prj.WebURL] = map[string]interface{}{
					"before": before,
					"after":  after,
				}
			}
		}

		// Exit the loop when we've seen all pages.
		if resp.CurrentPage >= resp.TotalPages {
			break
		}
		u.Sleep("10s")
		// Update the page number to get the next page.
		opt.Page = resp.NextPage
	}
	fmt.Println("Writting log ...")
	file_name := fmt.Sprintf("%s/set-image-expiry-%s.json.log", logDir, time.Now().Format(u.CleanStringDateLayout))
	err = ioutil.WriteFile(file_name, []byte(u.JsonDump(output, "    ")), 0777)
	u.CheckErr(err, "WriteFile set-image-expiry")
	fmt.Printf("Wrote report file %s\n", file_name)
}

func Equal_ContainerExpirationPolicyAttributes(a *gitlab.ContainerExpirationPolicyAttributes, b *gitlab.ContainerExpirationPolicy) bool {
	//fmt.Printf("%t = %t - %s = %s - %d = %d - '%s' = '%s' - '%s' = '%s'\n", *(a.Enabled), b.Enabled, *(a.Cadence), b.Cadence, *(a.KeepN), b.KeepN, *(a.NameRegexDelete), b.NameRegexDelete, *(a.NameRegexKeep), b.NameRegexKeep)
	// Change to false to update all of them :)
	return *(a.Enabled) == b.Enabled && *(a.Cadence) == b.Cadence && *(a.KeepN) == b.KeepN
	//*(a.NameRegexDelete) == b.NameRegexDelete && *(a.NameRegexKeep) == b.NameRegexKeep
	//Buggy The GUI shows the prj has NameRegexDelete but in here b.NameRegexDelete always empty!
}
