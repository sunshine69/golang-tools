package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"time"

	u "github.com/sunshine69/golang-tools/utils"
	"github.com/xanzy/go-gitlab"
)

var (
	GitLabToken string
)

func main() {
	GitLabToken = os.Getenv("GITLAB_TOKEN")
	git, err := gitlab.NewClient(GitLabToken, gitlab.WithBaseURL("https://code.go1.com.au/api/v4"))
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	opt := &gitlab.ListProjectsOptions{
		Search: gitlab.String("DevOps"),
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
	output := map[string][]interface{}{
		"nochange": []interface{}{},
		"changed": []interface{}{},
	}
	projectService := git.Projects
	for {
		projects, resp, err := projectService.ListProjects(opt)
		u.CheckErr(err, "Projects.ListProjects")

		for _, row := range projects {
			if row.ContainerRegistryEnabled && row.RepositoryAccessLevel == "enabled" && Equal_ContainerExpirationPolicyAttributes(&containerExpirationPolicyAttributes, row.ContainerExpirationPolicy) {
				fmt.Printf("Project ID %d - Already equal, no action\n", row.ID)
				output["nochange"] = append(output["nochange"], map[string]interface{}{
					"name":              row.Name,
					"url":               row.WebURL,
					"cadence":           "7d",
					"enabled":           row.ContainerExpirationPolicy.Enabled,
					"keep_n":            row.ContainerExpirationPolicy.KeepN,
					"older_than":        row.ContainerExpirationPolicy.OlderThan,
					"name_regex_delete": row.ContainerExpirationPolicy.NameRegexDelete,
					"name_regex_keep":   row.ContainerExpirationPolicy.NameRegexKeep,
					"next_run_at":       row.ContainerExpirationPolicy.NextRunAt.Format(u.AUTimeLayout),
				})
			} else {
				_, _, err := projectService.EditProject(row.ID, &editPrjOpt)
				u.CheckErr(err, "projectService.EditProject")
				output["changed"] = append(output["nochange"], map[string]interface{}{
					"name":              row.Name,
					"url":               row.WebURL,
					"cadence":           "7d",
					"enabled":           row.ContainerExpirationPolicy.Enabled,
					"keep_n":            row.ContainerExpirationPolicy.KeepN,
					"older_than":        row.ContainerExpirationPolicy.OlderThan,
					"name_regex_delete": row.ContainerExpirationPolicy.NameRegexDelete,
					"name_regex_keep":   row.ContainerExpirationPolicy.NameRegexKeep,
					"next_run_at":       row.ContainerExpirationPolicy.NextRunAt.Format(u.AUTimeLayout),
				})
				fmt.Printf("Updated %d\n", row.ID)
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
	err = ioutil.WriteFile(fmt.Sprintf("set-image-expiry-%s.log", time.Now().Format(u.CleanStringDateLayout)), []byte(u.JsonDump(output, "    ")), 0777)
	u.CheckErr(err, "WriteFile set-image-expiry")
}

func Equal_ContainerExpirationPolicyAttributes(a *gitlab.ContainerExpirationPolicyAttributes, b *gitlab.ContainerExpirationPolicy) bool {
	//fmt.Printf("%t = %t - %s = %s - %d = %d - '%s' = '%s' - '%s' = '%s'\n", *(a.Enabled), b.Enabled, *(a.Cadence), b.Cadence, *(a.KeepN), b.KeepN, *(a.NameRegexDelete), b.NameRegexDelete, *(a.NameRegexKeep), b.NameRegexKeep)
	// Change to false to update all of them :)
	return *(a.Enabled) == b.Enabled && *(a.Cadence) == b.Cadence && *(a.KeepN) == b.KeepN
	//*(a.NameRegexDelete) == b.NameRegexDelete && *(a.NameRegexKeep) == b.NameRegexKeep
	//Buggy The GUI shows the prj has NameRegexDelete but in here b.NameRegexDelete always empty!
}
