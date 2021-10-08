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
		_, tags := repoReg.Location, repoReg.Tags
		for _, t := range tags{
			oldImage := t.Location
			oldImagesList = append(oldImagesList, oldImage)
			extraName := u.Ternary( repoReg.Name == "", "", "/" + repoReg.Name )
			newImage := fmt.Sprintf(`%s%s:%s`, GetContainerRegistryBaseLocation(git, tempPrj.ID), extraName, t.Name )
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
	})
	if u.CheckNonErrIfMatch(err, "has already been taken", "BackupProjectRegistryImages") != nil {
		ps, _, err := git.Projects.ListProjects(&gitlab.ListProjectsOptions{
			Search: &tempPrjPath,
		}); u.CheckErr(err, "BackupProjectRegistryImages ListProjects")
		tempPrj = ps[0]
	}
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
	pd := ProjectDomainGet(map[string]string{"where": fmt.Sprintf("project_id = %d ORDER BY ts DESC LIMIT 1", gitlabProject.ID)})
	d := Domain{}
	d.GetOne(map[string]string{"where": fmt.Sprintf("gitlab_ns_id = %d", pd[0].DomainId)})
	gitlabDomainGroup, _, err := git.Groups.GetGroup(d.GitlabNamespaceId, nil)
	u.CheckErr(err, "TransferProject GetGroup")

	project := ProjectNew(gitlabProject.PathWithNamespace)

	existingGroupList := project.GetDomainList(git)
	existingRootGroup := existingGroupList[0]
	log.Printf("Check if existing root group %s is the same as the new group %s\n", existingRootGroup.FullPath, gitlabDomainGroup.FullPath)
	if existingRootGroup.FullPath == gitlabDomainGroup.FullPath {
		log.Printf("Matched - Project already be in correct group, do nothing\n")
		return
	}
	parentID := gitlabDomainGroup.ID
	lastNewGroup := gitlabDomainGroup
	//Replicate group path from old project => new one
	for idx, eg := range existingGroupList{
		if idx == 0 {
			log.Println("Copy the group vars - existingRootGroup => New Root Group")
			CopyGroupVars(git, eg, gitlabDomainGroup)
		} else {
			log.Printf("Check if sub group exists in the new tree")
			gs := GitlabNamespaceGet(map[string]string{"where":fmt.Sprintf("parent_id = %d AND path = '%s' ", parentID, eg.Path)})

			if len(gs) == 0 {
				log.Printf("Group does not exist, creating new group with parentID %d\n", parentID)
				lastNewGroup, _, err = git.Groups.CreateGroup(&gitlab.CreateGroupOptions{
					ParentID: &parentID,
					Path: &eg.Path,
					Name: &eg.Path, //Simplify, maybe search replace - with space and Captialize word?
				})
				if u.CheckNonErrIfMatch(err, "has already been taken", "") != nil {
					_gs,_,err := git.Groups.ListGroups(&gitlab.ListGroupsOptions{
						Search: &eg.Path,
						SkipGroups: []int{eg.ID},
					}); u.CheckErr(err, "TransferProject CreateGroup")
					lastNewGroup = _gs[0]
				}
				GitlabNamespaceNew(lastNewGroup.FullPath) //Update the table so re-run will detect that
			} else {
				log.Printf("Group exist, copy vars over")
				lastNewGroup,_,err = git.Groups.GetGroup(gs[0].GitlabNamespaceId, nil)
				u.CheckErr(err, "TransferProject GetGroup")
			}
			log.Printf("[DEBUG] lastNewGroup %s\n", u.JsonDump(lastNewGroup, "  "))
			CopyGroupVars(git, eg, lastNewGroup)
			parentID = lastNewGroup.ID
		}
	}
	// Transfer project won't work if the current project still have registry tag. We need to delete them
	// all before. Delete/backup is handled in MoveProjectRegistryImages func
	log.Println("Backup container reg and remove all existing tags")
	tempPrj := BackupProjectRegistryImages(git, gitlabProject)
	//Check the current project and be sure we don't have any image tags exists before transferring
	for {
		returnTag := true
		registryRepos, _, err := git.ContainerRegistry.ListRegistryRepositories(gitlabProject.ID, &gitlab.ListRegistryRepositoriesOptions{
			ListOptions: gitlab.ListOptions{
				Page: 1, PerPage: 500,
			},
			Tags: &returnTag,
			TagsCount: &returnTag,
		}); u.CheckErr(err, "MoveProjectRegistryImages ListRegistryRepositories")
		if len(registryRepos) == 0 {
			log.Printf("No repo, no tags")
			break
		} else {
			u.Sleep("15s")
		}
	}
	log.Printf("Transfer project to a new name space")
	_, res, err := git.Projects.TransferProject(gitlabProject.ID, &gitlab.TransferProjectOptions{
		Namespace: lastNewGroup.ID,
	})
	if u.CheckErrNonFatal(err, "TransferProject TransferGroup") != nil {
		log.Fatalf("[ERROR] gitlab response is %s\n", u.JsonDump(res, "  "))
	}
	project.DomainOwnershipConfirmed = 1; project.Update()

	log.Println("Move container image from temp")
	MoveProjectRegistryImages(git, tempPrj, gitlabProject)
	log.Println("Delete temporary project")
	_, err = git.Projects.DeleteProject(tempPrj.ID, nil)
	u.CheckErr(err, "TransferProject DeleteProject")
	log.Printf("TransferProject ID %d completed\n", gitlabProjectId)
}
