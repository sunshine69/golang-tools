package main

import (
	"fmt"
	"log"

	_ "github.com/mattn/go-sqlite3"
	"github.com/xanzy/go-gitlab"
	. "localhost.com/gitlab/model"
	u "localhost.com/utils"
)

func MoveProjectRegistryImages(git *gitlab.Client, currentPrj, tempPrj *gitlab.Project) {
	returnTag := true
	registryRepos, _, err := git.ContainerRegistry.ListRegistryRepositories(currentPrj.ID, &gitlab.ListRegistryRepositoriesOptions{
		ListOptions: gitlab.ListOptions{
			Page: 1, PerPage: 500,
		},
		Tags:      &returnTag,
		TagsCount: &returnTag,
	})
	u.CheckErr(err, "MoveProjectRegistryImages ListRegistryRepositories")

	oldImagesList := []string{}
	for _, repoReg := range registryRepos {
		_, tags := repoReg.Location, repoReg.Tags
		for _, t := range tags {
			oldImage := t.Location
			oldImagesList = append(oldImagesList, oldImage)
			extraName := u.Ternary(repoReg.Name == "", "", "/"+repoReg.Name)
			newImage := fmt.Sprintf(`%s%s:%s`, GetContainerRegistryBaseLocation(git, tempPrj.ID), extraName, t.Name)
			u.RunSystemCommand(fmt.Sprintf("docker pull %s", oldImage), true)
			u.RunSystemCommand(fmt.Sprintf("docker tag %s  %s", oldImage, newImage), true)
			u.RunSystemCommand(fmt.Sprintf("docker push %s", newImage), true)
		}
	}
	for _, repoReg := range registryRepos {
		_, err := git.ContainerRegistry.DeleteRegistryRepository(currentPrj.ID, repoReg.ID, nil)
		u.CheckErr(err, "MoveProjectRegistryImages DeleteRegistryRepository "+repoReg.String())
	}
	// Clean up local docker images after pushing
	for _, _oldImage := range oldImagesList {
		u.RunSystemCommand(fmt.Sprintf(`docker rmi %s`, _oldImage), false)
	}
}
func MoveProjectRegistryImagesUseShell(git *gitlab.Client, currentPrj, newPrj *gitlab.Project, user string) {
	returnTag := true
	registryRepos, _, err := git.ContainerRegistry.ListRegistryRepositories(currentPrj.ID, &gitlab.ListRegistryRepositoriesOptions{
		ListOptions: gitlab.ListOptions{
			Page: 1, PerPage: 500,
		},
		Tags:      &returnTag,
		TagsCount: &returnTag,
	})
	u.CheckErr(err, "MoveProjectRegistryImages ListRegistryRepositories")
	for _, repoReg := range registryRepos {
		repoImage := repoReg.Location
		extraName := u.Ternary(repoReg.Name == "", "", "/"+repoReg.Name)
		newImage := fmt.Sprintf(`%s%s`, GetContainerRegistryBaseLocation(git, newPrj.ID), extraName)
		u.RunSystemCommand(fmt.Sprintf("docker pull %s -a", repoImage), true)
		log.Printf("Pull %s completed\nStart to push ...\n", repoImage)

		u.SendMailSendGrid("Go1 GitlabDomain Automation <steve.kieu@go1.com>", user, fmt.Sprintf("Gitlab migration progress. Project %s", currentPrj.NameWithNamespace), fmt.Sprintf("We are going to push images From %s => %s", currentPrj.NameWithNamespace, newPrj.NameWithNamespace), "", []string{})

		u.RunSystemCommand(fmt.Sprintf(`docker images %s --format "docker tag {{.Repository}}:{{.Tag}} %s:{{.Tag}} && docker push %s:{{.Tag}}" | bash `, repoImage, newImage, newImage), true)
		log.Printf("Push %s completed\nStart to clean up ...\n", newImage)

		u.SendMailSendGrid("Go1 GitlabDomain Automation <steve.kieu@go1.com>", user, fmt.Sprintf("Gitlab migration progress. Project %s", currentPrj.NameWithNamespace), "", fmt.Sprintf("We are going to delete the container registry repository of the project name %s, ID %d. <b>This means your production k8s if using the old image will get errors. To minimize the outage of scaling please keep an eye for next email for action</b>", currentPrj.NameWithNamespace, currentPrj.ID), []string{})

		_, err := git.ContainerRegistry.DeleteRegistryRepository(currentPrj.ID, repoReg.ID, nil)
		u.CheckErr(err, "MoveProjectRegistryImages DeleteRegistryRepository "+repoReg.String())

		go u.RunSystemCommand(fmt.Sprintf(
			`docker images %s --format "docker rmi {{.Repository}}:{{.Tag}}" | bash
			docker images %s --format "docker rmi {{.Repository}}:{{.Tag}}" | bash`,
			repoImage, newImage), true)
		log.Printf("Cleanup %s completed\n", repoImage)
	}
}
func BackupProjectRegistryImages(git *gitlab.Client, p *gitlab.Project, user string) *gitlab.Project {
	tempPrjPath := fmt.Sprintf("%s-temp", p.Path)
	newNameSpaceId := ProjectDomainGet(map[string]string{"where": fmt.Sprintf("project_id = %d", p.ID)})[0].DomainId
	tempPrj, _, err := git.Projects.CreateProject(&gitlab.CreateProjectOptions{
		Path:        &tempPrjPath,
		NamespaceID: &newNameSpaceId,
	})
	if u.CheckNonErrIfMatch(err, "has already been taken", "BackupProjectRegistryImages") != nil {
		ps, _, err := git.Projects.ListProjects(&gitlab.ListProjectsOptions{
			Search: &tempPrjPath,
		})
		u.CheckErr(err, "BackupProjectRegistryImages ListProjects")
		tempPrj = ps[0]
	}
	MoveProjectRegistryImagesUseShell(git, p, tempPrj, user)
	return tempPrj
}

// Take a project_id and automate the transfer process. This should be run on a dashboard manually per project
// - Assign to new domain/team using gitlab API
// - Trigger a build of the new project with the last release state
// - Check and in theory manual qa and prod deploy should work and prod deploy as well
// - Remove the fork relationtionship of the new project to make it independent (if we use the fork model)

// This is run after we get all information for Team_Domain, Project_Domain manually updated by hand using spreadsheet. Project_Domain handled by UpdateProjectDomainFromCSVNext. Team_Domain by UpdateTeamDomainFromCSVNext

// This should run after the domain creation - that is no domain in the domain table having the gitlab_ns_id is 0 and has_team is 0. The func UpdateTeamDomainFromCSVNext should satisfy that.

func TransferProject(git *gitlab.Client, gitlabProjectId int, user string) {
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
	nonCopyableVars := []*gitlab.GroupVariable{}
	//Replicate group path from old project => new one
	for idx, eg := range existingGroupList {
		if idx == 0 {
			log.Println("Copy the group vars - existingRootGroup => New Root Group")
			nonCopyableVars = append(nonCopyableVars, CopyGroupVars(git, eg, gitlabDomainGroup)...)
		} else {
			log.Printf("Check if sub group exists in the new tree")
			gs := GitlabNamespaceGet(map[string]string{"where": fmt.Sprintf("parent_id = %d AND path = '%s' ", parentID, eg.Path)})

			if len(gs) == 0 {
				log.Printf("Group does not exist, creating new group with parentID %d\n", parentID)
				lastNewGroup, _, err = git.Groups.CreateGroup(&gitlab.CreateGroupOptions{
					ParentID: &parentID,
					Path:     &eg.Path,
					Name:     &eg.Path, //Simplify, maybe search replace - with space and Captialize word?
				})
				if u.CheckNonErrIfMatch(err, "has already been taken", "") != nil {
					_gs, _, err := git.Groups.ListGroups(&gitlab.ListGroupsOptions{
						Search:     &eg.Path,
						SkipGroups: []int{eg.ID},
					})
					u.CheckErr(err, "TransferProject CreateGroup")
					lastNewGroup = _gs[0]
				}
				GitlabNamespaceNew(lastNewGroup.FullPath) //Update the table so re-run will detect that
			} else {
				log.Printf("Group exist, copy vars over")
				lastNewGroup, _, err = git.Groups.GetGroup(gs[0].GitlabNamespaceId, nil)
				u.CheckErr(err, "TransferProject GetGroup")
			}
			log.Printf("[DEBUG] lastNewGroup %s\n", u.JsonDump(lastNewGroup, "  "))
			nonCopyableVars = append(nonCopyableVars, CopyGroupVars(git, eg, lastNewGroup)...)
			parentID = lastNewGroup.ID
		}
	}
	log.Printf("[DEBUG] nonCopyableVars: %s\n", u.JsonDump(nonCopyableVars, "  "))
	// Transfer project won't work if the current project still have registry tag. We need to delete them
	// all before. Delete/backup is handled in MoveProjectRegistryImages func
	log.Println("Backup container reg and remove all existing tags")
	tempPrj := BackupProjectRegistryImages(git, gitlabProject, user)
	//Check the current project and be sure we don't have any image tags exists before transferring
	WaitUntilAllRegistryTagCleared(git, gitlabProject.ID)

	log.Printf("Transfer project to a new name space")
	_, res, err := git.Projects.TransferProject(gitlabProject.ID, &gitlab.TransferProjectOptions{
		Namespace: lastNewGroup.ID,
	})
	if u.CheckErrNonFatal(err, "TransferProject TransferGroup") != nil {
		log.Fatalf("[ERROR] gitlab response is %s\n", u.JsonDump(res, "  "))
	}
	project.DomainOwnershipConfirmed = 1
	project.Update()

	log.Printf("[DEBUG] Copy nonCopyableVars into project\n")
	nonCopyableVars1 := CopyGroupVarIntoProject(git, nonCopyableVars, gitlabProject)
	if len(nonCopyableVars1) > 0 {
		log.Printf("[WARN] Can not copy these vars, it does exist but having different values\n%s\n", u.JsonDump(nonCopyableVars1, "  "))
	}

	u.SendMailSendGrid("Go1 GitlabDomain Automation <steve.kieu@go1.com>", user, fmt.Sprintf("Gitlab migration progress. Project %s", gitlabProject.NameWithNamespace), "", fmt.Sprintf("<h2>Migration %s completed</h2> However we still need to move the images back. <b>You can start to rebuild and deploy now</b>. If you do not want to rebuild and just want to re-deploy qa and prod, check the container registry to be sure the latest image tag has been copied over and you can run the deploy job manualy.", gitlabProject.NameWithNamespace), []string{})

	log.Println("Move container image from temp")
	MoveProjectRegistryImagesUseShell(git, tempPrj, gitlabProject, user)
	log.Println("Delete temporary project")

	WaitUntilAllRegistryTagCleared(git, tempPrj.ID)
	_, err = git.Projects.DeleteProject(tempPrj.ID, nil)
	u.CheckErr(err, "TransferProject DeleteProject")

	log.Printf("TransferProject ID %d completed\n", gitlabProjectId)
}
func WaitUntilAllRegistryTagCleared(git *gitlab.Client, gitlabProjectId int) {
	for {
		returnTag := true
		registryRepos, _, err := git.ContainerRegistry.ListRegistryRepositories(gitlabProject.ID, &gitlab.ListRegistryRepositoriesOptions{
			ListOptions: gitlab.ListOptions{
				Page: 1, PerPage: 500,
			},
			Tags:      &returnTag,
			TagsCount: &returnTag,
		})
		u.CheckErr(err, "MoveProjectRegistryImages ListRegistryRepositories")
		if len(registryRepos) == 0 {
			log.Printf("No repo, no tags")
			break
		} else {
			u.Sleep("15s")
		}
	}
}
