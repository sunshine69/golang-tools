package main

import (
	"fmt"
	"os"
	"log"
	"github.com/xanzy/go-gitlab"
	u "github.com/sunshine69/golang-tools/utils"
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
		//Search: gitlab.String("DevOps"),
		ListOptions: gitlab.ListOptions{
			PerPage: 50,
			Page:    1,
		},
	}
	Cadence := "1month"
	Enabled := true
	NameRegexDelete := ".*"
	NameRegexKeep := ""
	KeepN := 100
	OlderThan := "90d"

	containerExpirationPolicyAttributes := gitlab.ContainerExpirationPolicyAttributes{
		Cadence: &Cadence,
		Enabled: &Enabled,
		NameRegexDelete: &NameRegexDelete,
		NameRegexKeep: &NameRegexKeep,
		KeepN: &KeepN,
		OlderThan: &OlderThan,
	}
	editPrjOpt := gitlab.EditProjectOptions{
		ContainerExpirationPolicyAttributes: &containerExpirationPolicyAttributes,
	}

	projectService := git.Projects
	for{
		projects, resp, err := projectService.ListProjects(opt)
		u.CheckErr(err, "Projects.ListProjects")

		projectIDList := []int{}
		for _, row := range projects {
			projectIDList = append(projectIDList, row.ID )
			_, _, err := projectService.EditProject(row.ID, &editPrjOpt)
			u.CheckErr(err, "projectService.EditProject")
		}
		fmt.Printf("%v\n", projectIDList)


		// Exit the loop when we've seen all pages.
		if resp.CurrentPage >= resp.TotalPages {
			break
		}
		u.Sleep("10s")
		// Update the page number to get the next page.
		opt.Page = resp.NextPage
	}
}
