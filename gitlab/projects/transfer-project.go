package main

import (
	"log"
	"fmt"
	u "localhost.com/utils"
	. "localhost.com/gitlab/model"
	_ "github.com/mattn/go-sqlite3"
	"github.com/xanzy/go-gitlab"
)
func MoveProjectRegistryImages(git *gitlab.Client, currentPrj, tempPrj *gitlab.Project ) {
	returnTag := true
	registryRepos, _, err := git.ContainerRegistry.ListRegistryRepositories(currentPrj.ID, &gitlab.ListRegistryRepositoriesOptions{
		ListOptions: gitlab.ListOptions{
			Page: 1, PerPage: 500,
		},
		Tags: &returnTag,
		TagsCount: &returnTag,
	}); u.CheckErr(err, "MoveProjectRegistryImages ListRegistryRepositories")

	oldImagesList := []string{}
	for _, repoReg := range registryRepos {
		location, tags := repoReg.Location, repoReg.Tags
		for _, t := range tags{
			oldImage := fmt.Sprintf(`%s:%s`, location, t)
			oldImagesList = append(oldImagesList, oldImage)
			extraName := u.Ternary( repoReg.Name == "", "", "/" + repoReg.Name )
			newImage := fmt.Sprintf(`%s%s:%s`, GetContainerRegistryBaseLocation(git, tempPrj.ID), extraName, t )
			u.RunSystemCommand( fmt.Sprintf("docker pull %s", oldImage) , true)
			u.RunSystemCommand(fmt.Sprintf("docker tag %s  %s", oldImage, newImage ), true)
			u.RunSystemCommand( fmt.Sprintf("docker push %s", newImage), true )
		}
	}
	for _, repoReg := range registryRepos {
		_, err := git.ContainerRegistry.DeleteRegistryRepository(currentPrj.ID, repoReg.ID, nil)
		u.CheckErr(err, "MoveProjectRegistryImages DeleteRegistryRepository " + repoReg.String())
	}
	// Clean up local docker images after pushing
	for _, _oldImage := range oldImagesList{
		u.RunSystemCommand(fmt.Sprintf(`docker rmi %s`, _oldImage), false)
	}
}
func BackupProjectRegistryImages(git *gitlab.Client, p *gitlab.Project) *gitlab.Project {
	tempPrjPath := fmt.Sprintf("%s-temp", p.Path)
	newNameSpaceId := ProjectDomainGet(map[string]string{"where": fmt.Sprintf("project_id = %d", p.ID)})[0].DomainId
	tempPrj, _, err := git.Projects.CreateProject(&gitlab.CreateProjectOptions{
		Path: &tempPrjPath,
		NamespaceID: &newNameSpaceId,
	}); u.CheckErr(err, "BackupProjectRegistryImages CreateProject")
	MoveProjectRegistryImages(git, p, tempPrj)
	return tempPrj
}
// Take a project_id and automate the transfer process. This should be run on a dashboard manually per project
// - Assign to new domain/team using gitlab API
// - Trigger a build of the new project with the last release state
// - Check and in theory manual qa and prod deploy should work and prod deploy as well
// - Remove the fork relationtionship of the new project to make it independent (if we use the fork model)

// This is run after we get all information for Team_Domain, Project_Domain manually updated by hand using spreadsheet. Project_Domain handled by UpdateProjectDomainFromCSVNext. Team_Domain by UpdateTeamDomainFromCSVNext

// This should run after the domain creation - that is no domain in the domain table having the gitlab_ns_id is 0 and has_team is 0. The func UpdateTeamDomainFromCSVNext should satisfy that.

func TransferProject(git *gitlab.Client, gitlabProjectId int) {
	log.Printf("TransferProject ID %d started\n", gitlabProjectId)
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
	// Transfer project won't work if the current project still have registry tag. We need to delete them
	// all before. Delete/backup is handled in MoveProjectRegistryImages func
	log.Println("Backup container reg and remove all existing tags")
	tempPrj := BackupProjectRegistryImages(git, gitlabProject)
	log.Printf("Transfer project to a new name space")
	_, res, err := git.Projects.TransferProject(gitlabProject.ID, &gitlab.TransferProjectOptions{
		Namespace: gitlabDomainGroup.ID,
	})
	if u.CheckErrNonFatal(err, "TransferProject TransferGroup") != nil {
		log.Fatalf("[ERROR] gitlab response is %s\n", u.JsonDump(res, "  "))
	}
	log.Println("Move container image from temp")
	MoveProjectRegistryImages(git, tempPrj, gitlabProject)
	log.Println("Delete temporary project")
	_, err = git.Projects.DeleteProject(tempPrj.ID, nil)
	u.CheckErr(err, "TransferProject DeleteProject")
	log.Printf("TransferProject ID %d completed\n", gitlabProjectId)
}
