package main

import (
	"log"
	"fmt"
	u "localhost.com/utils"
	. "localhost.com/gitlab/model"
	_ "github.com/mattn/go-sqlite3"
	"github.com/xanzy/go-gitlab"
)
// Take a project_id and automate the transfer process. This should be run on a dashboard manually per project
// - Assign to new domain/team using gitlab API
// - Trigger a build of the new project with the last release state
// - Check and in theory manual qa and prod deploy should work and prod deploy as well
// - Remove the fork relationtionship of the new project to make it independent (if we use the fork model)

// This is run after we get all information for Team_Domain, Project_Domain manually updated by hand using spreadsheet. Project_Domain handled by UpdateProjectDomainFromCSVNext. Team_Domain by UpdateTeamDomainFromCSVNext

// This should run after the domain creation - that is no domain in the domain table having the gitlab_ns_id is 0 and has_team is 0. The func UpdateTeamDomainFromCSVNext should satisfy that.

func TransferProject(git *gitlab.Client, gitlabProjectId int) {
	gitlabProject, _, err := git.Projects.GetProject(gitlabProjectId, nil)
	u.CheckErr(err, "TransferProject Projects.GetProject")
	// Get the domain for this project from Project_Domain relationship
	pd := ProjectDomainGet(map[string]string{"where": fmt.Sprintf("project_id = %d", gitlabProject.ID)})
	// Make sure One project only link with One root domain
	if len(pd) > 1 {
		log.Fatalf("[ERROR] A project should not have more than one domains. Project %s\n", u.JsonDump( ProjectGet(map[string]string{"where":fmt.Sprintf("pid = %d", gitlabProjectId)}), "  "))
	}
	d := Domain{}
	d.GetOne(map[string]string{"where": fmt.Sprintf("id = %d", pd[0].DomainId)})
	if d.GitlabNamespaceId == 0 {
		log.Fatalf("[ERROR] Domain not created yet. You have to run this UpdateTeamDomainFromCSVNext first. Domain %s\n", u.JsonDump( d, "  "))
	}
	gitlabDomainGroup, _, err := git.Groups.GetGroup(d.GitlabNamespaceId, nil)
	u.CheckErr(err, "TransferProject GetGroup")
	// Transfer project to a new name space
	_, res, err := git.Projects.TransferProject(gitlabProject.ID, &gitlab.TransferProjectOptions{
		Namespace: gitlabDomainGroup.ID,
	})
	if u.CheckErrNonFatal(err, "TransferProject TransferGroup") != nil {
		log.Fatalf("[ERROR] gitlab response is %s\n", u.JsonDump(res, "  "))
	}
}

