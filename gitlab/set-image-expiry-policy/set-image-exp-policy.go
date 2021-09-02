package main

import (
	"fmt"
	"log"
	"os"

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
		//Search: gitlab.String("DevOps"),
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

	projectService := git.Projects
	for {
		projects, resp, err := projectService.ListProjects(opt)
		u.CheckErr(err, "Projects.ListProjects")

		projectIDList := []int{}
		for _, row := range projects {
			if (Equal_ContainerExpirationPolicyAttributes(&containerExpirationPolicyAttributes, row.ContainerExpirationPolicy) ) {
				fmt.Printf("Project ID %d - Already equal, no action\n", row.ID)
			} else {
				projectIDList = append(projectIDList, row.ID)
				_, _, err := projectService.EditProject(row.ID, &editPrjOpt)
				u.CheckErr(err, "projectService.EditProject")
				fmt.Printf("Updated %d\n",row.ID)
			}
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

func Equal_ContainerExpirationPolicyAttributes (a *gitlab.ContainerExpirationPolicyAttributes, b *gitlab.ContainerExpirationPolicy) bool {
    //fmt.Printf("%t = %t - %s = %s - %d = %d - '%s' = '%s' - '%s' = '%s'\n", *(a.Enabled), b.Enabled, *(a.Cadence), b.Cadence, *(a.KeepN), b.KeepN, *(a.NameRegexDelete), b.NameRegexDelete, *(a.NameRegexKeep), b.NameRegexKeep)

	return *(a.Enabled) == b.Enabled && *(a.Cadence) == b.Cadence && *(a.KeepN) == b.KeepN
		//*(a.NameRegexDelete) == b.NameRegexDelete && *(a.NameRegexKeep) == b.NameRegexKeep
        //Buggy The GUI shows the prj has NameRegexDelete but in here b.NameRegexDelete always empty!
}
