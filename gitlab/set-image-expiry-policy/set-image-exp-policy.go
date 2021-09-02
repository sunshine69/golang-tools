package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"time"

	u "github.com/sunshine69/golang-tools/utils"
	"github.com/xanzy/go-gitlab"
)

var (
	GitLabToken, projectSearchStr string
)

func main() {
	flag.StringVar(&projectSearchStr, "project-search-string", "DevOps", "Project search Str. Empty means everything")
	flag.Parse()

	GitLabToken = os.Getenv("GITLAB_TOKEN")
	git, err := gitlab.NewClient(GitLabToken, gitlab.WithBaseURL("https://code.go1.com.au/api/v4"))
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
	Cadence := "7d"
	Enabled := true
	NameRegexDelete := ".*"
	NameRegexKeep := ""
	KeepN := 100
	OlderThan := "90d"

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
	before, after := []interface{}{}, []interface{}{}
	output := map[string]interface{}{
		"nochange": []interface{}{},
		"changed":  map[string]interface{} {
			"before": &before,
			"after" : &after,
		},
	}
	projectService := git.Projects
	for {
		projects, resp, err := projectService.ListProjects(opt)
		u.CheckErr(err, "Projects.ListProjects")

		for _, row := range projects {
			if row.ContainerRegistryEnabled && row.RepositoryAccessLevel == "enabled" && Equal_ContainerExpirationPolicyAttributes(&containerExpirationPolicyAttributes, row.ContainerExpirationPolicy) {
				fmt.Printf("Project ID %d - Already equal, no action\n", row.ID)
				output["nochange"] = append(output["nochange"].([]interface{}), map[string]interface{}{
					"name":              row.Name,
					"url":               row.WebURL,
					"cadence":           row.ContainerExpirationPolicy.Cadence,
					"enabled":           row.ContainerExpirationPolicy.Enabled,
					"keep_n":            row.ContainerExpirationPolicy.KeepN,
					"older_than":        row.ContainerExpirationPolicy.OlderThan,
					"name_regex_delete": row.ContainerExpirationPolicy.NameRegexDelete,
					"name_regex_keep":   row.ContainerExpirationPolicy.NameRegexKeep,
					"next_run_at":       row.ContainerExpirationPolicy.NextRunAt.Format(u.AUTimeLayout),
				})
			} else {
				fmt.Printf("Project ID %d - Action Update\n", row.ID)
				// before := output["changed"].(map[string]interface{})["before"].([]map[string]interface{})
				before = append(before, map[string]interface{}{
					"id":				 row.ID,
					"name":              row.Name,
					"url":               row.WebURL,
					"cadence":           row.ContainerExpirationPolicy.Cadence,
					"enabled":           row.ContainerExpirationPolicy.Enabled,
					"keep_n":            row.ContainerExpirationPolicy.KeepN,
					"older_than":        row.ContainerExpirationPolicy.OlderThan,
					"name_regex_delete": row.ContainerExpirationPolicy.NameRegexDelete,
					"name_regex_keep":   row.ContainerExpirationPolicy.NameRegexKeep,
					"next_run_at":       row.ContainerExpirationPolicy.NextRunAt.Format(u.AUTimeLayout),
				})
				_, _, err := projectService.EditProject(row.ID, &editPrjOpt)
				u.CheckErr(err, "projectService.EditProject")
				fmt.Printf("Updated %d\n", row.ID)
				_prj, _, err := projectService.GetProject(row.ID, nil )
				u.CheckErr(err, "projectService.GetProject")
				// after := output["changed"].(map[string]interface{})["after"].([]map[string]interface{})
				after = append(after, map[string]interface{}{
					"id": 				 _prj.ID,
					"name":              _prj.Name,
					"url":               _prj.WebURL,
					"cadence":           _prj.ContainerExpirationPolicy.Cadence,
					"enabled":           _prj.ContainerExpirationPolicy.Enabled,
					"keep_n":            _prj.ContainerExpirationPolicy.KeepN,
					"older_than":        _prj.ContainerExpirationPolicy.OlderThan,
					"name_regex_delete": _prj.ContainerExpirationPolicy.NameRegexDelete,
					"name_regex_keep":   _prj.ContainerExpirationPolicy.NameRegexKeep,
					"next_run_at":       _prj.ContainerExpirationPolicy.NextRunAt.Format(u.AUTimeLayout),
				})
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
	file_name := fmt.Sprintf("set-image-expiry-%s.json", time.Now().Format(u.CleanStringDateLayout))
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
