package main

import (
	"strings"
	"time"
	"regexp"
	"errors"
	"fmt"
	"log"

	_ "github.com/mattn/go-sqlite3"
	"github.com/xanzy/go-gitlab"
	. "localhost.com/gitlab/model"
	u "localhost.com/utils"
)
//Move registry images from current prj to new one, ops can be pull|push|both default is both
func MoveProjectRegistryImages(git *gitlab.Client, currentPrj, newPrj *gitlab.Project, user, ops string) (int, error) {
	if ops == "" { ops = "both" }
	returnTag, processImageCount := true, 0
	registryRepos, _, err := git.ContainerRegistry.ListRegistryRepositories(currentPrj.ID, &gitlab.ListRegistryRepositoriesOptions{
		ListOptions: gitlab.ListOptions{
			Page: 1, PerPage: 100,
		},
		Tags:      &returnTag,
		TagsCount: &returnTag,
	})
	u.CheckErr(err, "MoveProjectRegistryImages ListRegistryRepositories")

	oldImagesList := []string{}
	_emailSubj := ""
	switch ops {
	case "pull":
		_emailSubj = fmt.Sprintf("We are going to pull images From %s => %s", currentPrj.NameWithNamespace, "local disk")
	case "push":
		_emailSubj = fmt.Sprintf("We are going to push images From %s => %s", "local disk", newPrj.NameWithNamespace)
	case "both":
		_emailSubj = fmt.Sprintf("We are going to pull/push images From %s => %s", currentPrj.NameWithNamespace, newPrj.NameWithNamespace)
	}
	for _, repoReg := range registryRepos {
		u.SendMailSendGrid(AppConfig["EmailFrom"].(string), user, fmt.Sprintf("Gitlab migration progress. Project %s", currentPrj.NameWithNamespace), _emailSubj, "", []string{})
		_, tags := repoReg.Location, repoReg.Tags

		comChannel := make(chan int)
		defer close(comChannel)
		currentJobCountInBatch := 0
		for _idx, t := range tags {
			oldImage := t.Location
			oldImagesList = append(oldImagesList, oldImage)
			extraName := u.Ternary(repoReg.Name == "", "", "/"+repoReg.Name)
			newImage := fmt.Sprintf(`%s%s:%s`, GetContainerRegistryBaseLocation(git, newPrj.ID), extraName, t.Name)

			currentJobCountInBatch++
			go func(idx int, oldImage, newImage string) {
				if (ops == "pull") || (ops == "both") {
					for _trycount := 0; _trycount < 5; _trycount++ {
						if o, err := u.RunSystemCommandV2(fmt.Sprintf("docker pull %s", oldImage), true); err != nil {
							log.Println(o)
							if _trycount == 4 {
								log.Printf("ERROR maximum tries reached. I am tired. But I will move on\n")
							} else {
								log.Printf("ERROR try %d with message %s. Will retry after 1 minutes\n", _trycount, o)
								time.Sleep(60 * time.Second)
							}
							comChannel <- idx
							return
						}
						if oldImage != newImage {
							u.RunSystemCommand(fmt.Sprintf("docker tag %s  %s", oldImage, newImage), true)
						}
					}
				}
				if (ops == "push") || (ops == "both") {
					for _trycount := 0; _trycount < 5; _trycount++ {
						msg, err := u.RunSystemCommandV2(fmt.Sprintf("docker push %s", newImage), true)
						if err != nil {
							if _trycount == 4 {
								log.Fatalf("ERROR maximum tries reached. I am tired\n")
							} else{
								log.Printf("ERROR try %d with message %s. Will retry after 1 minutes\n", _trycount, msg)
								time.Sleep(60 * time.Second)
							}
						} else {
							break
						}
					}
					comChannel <- idx
				}
			}(_idx, oldImage, newImage)

			if (currentJobCountInBatch > 0) && (currentJobCountInBatch % int(AppConfig["BatchSize"].(float64)) == 0) {
				j := <-comChannel
				processImageCount++
				fmt.Printf("job %d completed.\n", j)
				currentJobCountInBatch--
			}
		}
		if currentJobCountInBatch > 0 {
			//Flush the rest
			for j := range comChannel {
				fmt.Printf("job %d completed\n", j)
				currentJobCountInBatch--
				processImageCount++
				if currentJobCountInBatch == 0 {
					break
				}
			}
		}
		//If we do not process any images but in the registry has images means all images are corrupted. We should error here
		if (processImageCount == 0) && (len(oldImagesList) > 0) {
			errMsg := "[ERROR] CRITICAL We have images in the repo but we can not move any. This implies all images are corrupted"
			u.SendMailSendGrid(AppConfig["EmailFrom"].(string), user, fmt.Sprintf("Gitlab migration progress. Project %s", currentPrj.NameWithNamespace), "", errMsg, []string{})
			return 0, errors.New(errMsg)
		}
	}
	for _, repoReg := range registryRepos {
		u.SendMailSendGrid(AppConfig["EmailFrom"].(string), user, fmt.Sprintf("Gitlab migration progress. Project %s", currentPrj.NameWithNamespace), "", fmt.Sprintf("We are going to delete the container registry repository of the project name %s, ID %d. <b>This means your production k8s if using the old image will get errors. To minimize the outage of scaling please keep an eye for next email for action</b>", currentPrj.NameWithNamespace, currentPrj.ID), []string{})
		_, err := git.ContainerRegistry.DeleteRegistryRepository(currentPrj.ID, repoReg.ID, nil)
		u.CheckErr(err, "MoveProjectRegistryImages DeleteRegistryRepository "+repoReg.String())
	}
	// Clean up local docker images after pushing
	for _, _oldImage := range oldImagesList {
		go u.RunSystemCommandV2(fmt.Sprintf(`docker rmi %s`, _oldImage), false)
	}
	return processImageCount, nil
}
func MoveProjectRegistryImagesUseShell(git *gitlab.Client, currentPrj, newPrj *gitlab.Project, user string) {
	returnTag := true
	registryRepos, _, err := git.ContainerRegistry.ListRegistryRepositories(currentPrj.ID, &gitlab.ListRegistryRepositoriesOptions{
		ListOptions: gitlab.ListOptions{
			Page: 1, PerPage: 100,
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

		u.SendMailSendGrid(AppConfig["EmailFrom"].(string), user, fmt.Sprintf("Gitlab migration progress. Project %s", currentPrj.NameWithNamespace), fmt.Sprintf("We are going to push images From %s => %s", currentPrj.NameWithNamespace, newPrj.NameWithNamespace), "", []string{})

		u.RunSystemCommand(fmt.Sprintf(`docker images %s --format "docker tag {{.Repository}}:{{.Tag}} %s:{{.Tag}} && docker push %s:{{.Tag}}" | bash `, repoImage, newImage, newImage), true)
		log.Printf("Push %s completed\nStart to clean up ...\n", newImage)

		u.SendMailSendGrid(AppConfig["EmailFrom"].(string), user, fmt.Sprintf("Gitlab migration progress. Project %s", currentPrj.NameWithNamespace), "", fmt.Sprintf("We are going to delete the container registry repository of the project name %s, ID %d. <b>This means your production k8s if using the old image will get errors. To minimize the outage of scaling please keep an eye for next email for action</b>", currentPrj.NameWithNamespace, currentPrj.ID), []string{})

		_, err := git.ContainerRegistry.DeleteRegistryRepository(currentPrj.ID, repoReg.ID, nil)
		u.CheckErr(err, "MoveProjectRegistryImages DeleteRegistryRepository "+repoReg.String())

		go u.RunSystemCommand(fmt.Sprintf(
			`docker images %s --format "docker rmi {{.Repository}}:{{.Tag}}" | bash
			docker images %s --format "docker rmi {{.Repository}}:{{.Tag}}" | bash`,
			repoImage, newImage), true)
		log.Printf("Cleanup %s completed\n", repoImage)
	}
}
// This create a temporary project and backup the image there
func BackupProjectRegistryImages(git *gitlab.Client, p *gitlab.Project, user string) (*gitlab.Project, error) {
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
	// MoveProjectRegistryImagesUseShell(git, p, tempPrj, user)
	_, err = MoveProjectRegistryImages(git, p, tempPrj, user, "")
	return tempPrj, err
}
// Take a project_id and automate the transfer process. This should be run on a dashboard manually per project
// - Assign to new domain/team using gitlab API
// - Trigger a build of the new project with the last release state
// - Check and in theory manual qa and prod deploy should work and prod deploy as well
// - Remove the fork relationtionship of the new project to make it independent (if we use the fork model)

// This is run after we get all information for Team_Domain, Project_Domain manually updated by hand using spreadsheet. Project_Domain handled by UpdateProjectDomainFromCSVNext. Team_Domain by UpdateTeamDomainFromCSVNext

// This should run after the domain creation - that is no domain in the domain table having the gitlab_ns_id is 0 and has_team is 0. The func UpdateTeamDomainFromCSVNext should satisfy that.

func TransferProject(git *gitlab.Client, gitlabProjectId int, user string) {
	gitlabProject, _, err := git.Projects.GetProject(gitlabProjectId, nil)
	if gitlabProject.Archived {
		log.Printf("[ERROR] Project %s is in Archived mode, skipping\n", gitlabProject.NameWithNamespace)
		return
	}
	log.Printf("TransferProject ID %d, name %s started\n", gitlabProjectId, gitlabProject.NameWithNamespace)
	u.CheckErr(err, "TransferProject Projects.GetProject")
	// Get the domain for this project from Project_Domain relationship
	pd := ProjectDomainGet(map[string]string{"where": fmt.Sprintf("project_id = %d ORDER BY ts DESC LIMIT 1", gitlabProject.ID)})
	d := Domain{}
	d.GetOne(map[string]string{"where": fmt.Sprintf("gitlab_ns_id = %d", pd[0].DomainId)})
	gitlabDomainGroup, _, err := git.Groups.GetGroup(d.GitlabNamespaceId, nil)
	u.CheckErr(err, "TransferProject GetGroup")

	project := ProjectNew(gitlabProject.PathWithNamespace)

	existingGroupList := project.GetDomainList(git)
	existingGroupListNames := []string{}
	for _, _name := range existingGroupList { existingGroupListNames = append(existingGroupListNames, _name.FullPath ) }
	log.Printf("[DEBUG] pid:%d existingGroupList %s\n", project.ID, u.JsonDump(existingGroupListNames, "  "))
	existingRootGroup := existingGroupList[0]
	log.Printf("pid: %d Check if existing root group %s is the same as the new group %s\n", gitlabProjectId, existingRootGroup.FullPath, gitlabDomainGroup.FullPath)
	if existingRootGroup.FullPath == gitlabDomainGroup.FullPath {
		log.Printf("pid: %d Matched - Project already be in correct group, do nothing\n", gitlabProjectId)
		return
	}
	parentID := gitlabDomainGroup.ID
	lastNewGroup := gitlabDomainGroup
	nonCopyableVars := []*gitlab.GroupVariable{}
	//Replicate group path from old project => new one
	for idx, eg := range existingGroupList {
		if idx == 0 {
			log.Printf("pid: %d Copy the group vars - existingRootGroup '%s' => New Root Group '%s'\n", gitlabProjectId, eg.Name, gitlabDomainGroup.Name)
			nonCopyableVars = append(nonCopyableVars, CopyGroupVars(git, eg, gitlabDomainGroup)...)
		} else {
			log.Printf("pid: %d Check if sub group %s exists in the new tree from db\n", gitlabProjectId, eg.Path)
			gs := GitlabNamespaceGet(map[string]string{"where": fmt.Sprintf("parent_id = %d AND path = '%s' ", parentID, eg.Path)})
			log.Printf("[DEBUG] pid: %d got list namespace from table %s\n", gitlabProjectId, u.JsonDump(gs, "  "))
			if len(gs) == 0 {
				log.Printf("pid: %d Group %s does not exist, trying to create new group path '%s' with parentID %d\n", gitlabProjectId, eg.FullName, eg.Path, parentID)
				lastNewGroup, res, err := git.Groups.CreateGroup(&gitlab.CreateGroupOptions{
					ParentID: &parentID,
					Path:     &eg.Path,
					Name:     &eg.Path, //Simplify, maybe search replace - with space and Captialize word?
				})
				log.Printf("[DEBUG] pid: %d response from gitlab to create group path %s with parentID %d - %s\n",gitlabProjectId, eg.Path, parentID, u.JsonDump(res, "  "))
				if u.CheckNonErrIfMatch(err, "has already been taken", "") != nil {
					log.Printf("Group %s seems to exists in gitlab but not in database as we hit error from gitlab says 'has already been taken'\n", eg.Path)
					_gs, _, err := git.Groups.ListGroups(&gitlab.ListGroupsOptions{
						Search:     &eg.Path,
					})
					u.CheckErr(err, "TransferProject")
					for _, _g := range _gs {
						if _g.ParentID == parentID {
							lastNewGroup = _g
							break
						}
					}
					log.Printf("Did re-get the group with path %s and parentID %d. Output: %s\n", eg.Path, parentID, u.JsonDump(lastNewGroup, "  "))
				}
				p := GitlabNamespaceNew(lastNewGroup.FullPath) //Update the table so re-run will detect that
				p.Name, p.ParentId, p.Path, p.FullPath, p.GitlabNamespaceId = lastNewGroup.Name, lastNewGroup.ParentID, lastNewGroup.Path, lastNewGroup.FullPath, lastNewGroup.ID
				p.Update()
				// GitlabGroup2Team(git, &p)
				// GitlabGroup2Domain(git, &p)
			} else {
				log.Printf("pid: %d Group %s exist. Use this groupID %d from database to get group from gitlab\n", gitlabProjectId, eg.Path, gs[0].GitlabNamespaceId )
				lastNewGroup, _, err = git.Groups.GetGroup(gs[0].GitlabNamespaceId, nil)
				u.CheckErr(err, "TransferProject GetGroup")
			}
			log.Printf("[DEBUG] pid: %d lastNewGroup %s\n", gitlabProjectId, u.JsonDump(lastNewGroup, "  "))
			log.Printf("pid: %d Copy the group vars - existingRootGroup '%s' => New Root Group '%s'\n", gitlabProjectId, eg.Name, lastNewGroup.Name)
			nonCopyableVars = append(nonCopyableVars, CopyGroupVars(git, eg, lastNewGroup)...)
			parentID = lastNewGroup.ID
		}
	}
	log.Printf("[DEBUG] pid: %d nonCopyableVars: %s\n", gitlabProjectId, u.JsonDump(nonCopyableVars, "  "))
	// Transfer project won't work if the current project still have registry tag. We need to delete them
	// all before. Delete/backup is handled in MoveProjectRegistryImages func
	log.Printf("pid: %d - Backup container reg and remove all existing tags\n", gitlabProjectId)
	tempPrj, err := BackupProjectRegistryImages(git, gitlabProject, user)
	if u.CheckErrNonFatal(err, "TransferProject BackupProjectRegistryImages") != nil { return }
	//Check the current project and be sure we don't have any image tags exists before transferring
	WaitUntilAllRegistryTagCleared(git, gitlabProject.ID)

	log.Printf("pid:%d - Transfer project to a new name space %s with id %d\n", gitlabProjectId, lastNewGroup.FullName, lastNewGroup.ID)
	_, res, err := git.Projects.TransferProject(gitlabProject.ID, &gitlab.TransferProjectOptions{
		Namespace: lastNewGroup.ID,
	})
	if u.CheckErrNonFatal(err, "TransferProject TransferGroup") != nil {
		log.Fatalf("[ERROR] pid:%d gitlab response is %s. Error object: %s\n", gitlabProject.ID, u.JsonDump(res, "  "), u.JsonDump(err, "  "))
	} else {
		log.Printf("[DEBUG] pid:%d gitlab response is %s\n", gitlabProject.ID, u.JsonDump	(res, "  "))
	}
	project.DomainOwnershipConfirmed = 1
	project.Update()

	log.Printf("[DEBUG] pid:%d Copy nonCopyableVars into project\n", gitlabProjectId)
	nonCopyableVars1 := CopyGroupVarIntoProject(git, nonCopyableVars, gitlabProject)
	if len(nonCopyableVars1) > 0 {
		log.Printf("[WARN] pid:%d Can not copy these vars, it does exist but having different values\n%s\n", gitlabProjectId, u.JsonDump(nonCopyableVars1, "  "))
	}

	u.SendMailSendGrid(AppConfig["EmailFrom"].(string), user, fmt.Sprintf("Gitlab migration progress. Project %s", gitlabProject.NameWithNamespace), "", fmt.Sprintf("<h2>Migration %s completed</h2> However we still need to move the images back. <b>You can start to rebuild and deploy now</b>. If you do not want to rebuild and just want to re-deploy qa and prod, check the container registry to be sure the latest image tag has been copied over and you can run the deploy job manualy.", gitlabProject.NameWithNamespace), []string{})

	log.Printf("pid:%d - Move container image from temp\n", gitlabProjectId)
	// MoveProjectRegistryImagesUseShell(git, tempPrj, gitlabProject, user)
	_, err = MoveProjectRegistryImages(git, tempPrj, gitlabProject, user, "")
	if err != nil {
		log.Printf("[ERROR] while copying back the images from local to the project. Please check and re-run the docker push command\n")
	}
	log.Printf("pid:%d - Delete temporary project\n", gitlabProjectId)

	WaitUntilAllRegistryTagCleared(git, tempPrj.ID)
	_, err = git.Projects.DeleteProject(tempPrj.ID, nil)
	u.CheckErr(err, "TransferProject DeleteProject")

	log.Printf("TransferProject ID %d completed\n", gitlabProjectId)
}
func WaitUntilAllRegistryTagCleared(git *gitlab.Client, gitlabProjectId int) {
	for {
		returnTag := true
		registryRepos, _, err := git.ContainerRegistry.ListRegistryRepositories(gitlabProjectId, &gitlab.ListRegistryRepositoriesOptions{
			ListOptions: gitlab.ListOptions{
				Page: 1, PerPage: 100,
			},
			Tags:      &returnTag,
			TagsCount: &returnTag,
		})
		u.CheckErr(err, "WaitUntilAllRegistryTagCleared ListRegistryRepositories")
		if len(registryRepos) == 0 {
			log.Printf("No repo, no tags")
			break
		} else {
			u.Sleep("15s")
		}
	}
}
// Just transfer a project to new path and get/push images. No variable copying or replicate domain in between, assume the new path has been created already
//newPath should not started with slash /
func TransferProjectQuick(git *gitlab.Client, gitlabProjectId int, newPath, extraRegistryImageName string) {
	gitlabProject, _, err := git.Projects.GetProject(gitlabProjectId, nil)
	if gitlabProject.Archived {
		log.Printf("[ERROR] Project %s is in Archived mode, skipping\n", gitlabProject.NameWithNamespace)
		return
	}
	u.CheckErr(err, "TransferProjectQuick GetProject")
	log.Printf("TransferProject ID %d, name %s to new path: %s started\n", gitlabProjectId, gitlabProject.NameWithNamespace, newPath)
	d := GitlabNamespaceGet(map[string]string{"where":"full_path = '"+newPath+"'"})
	if ! u.Assert(len(d) == 1, "Expect to get 1 domain", false) {
		log.Printf("[ERROR] Can not find the group with full_path: %s make sure the path exists\n", newPath)
		return
	}
	gitlabDomainGroup, _, err := git.Groups.GetGroup(d[0].GitlabNamespaceId, nil)
	u.CheckErr(err, "TransferProject GetGroup")

	_, err = MoveProjectRegistryImages(git, gitlabProject, gitlabProject, "None", "pull")
	if u.CheckErrNonFatal(err, "TransferProjectQuick") != nil {
		return
	}
	returnTag := true
	registryRepos, _, err := git.ContainerRegistry.ListRegistryRepositories(gitlabProject.ID, &gitlab.ListRegistryRepositoriesOptions{
		ListOptions: gitlab.ListOptions{
			Page: 1, PerPage: 100,
		},
		Tags:      &returnTag,
		TagsCount: &returnTag,
	})
	u.CheckErr(err, "TransferProjectQuick ListRegistryRepositories")
	repoImages := []string{}
	for _, repoReg := range registryRepos {
		repoImage := repoReg.Location
		_, err := git.ContainerRegistry.DeleteRegistryRepository(gitlabProject.ID, repoReg.ID, nil)
		u.CheckErr(err, "TransferProjectQuick DeleteRegistryRepository "+repoReg.String())
		repoImages = append(repoImages, repoImage)
	}
	WaitUntilAllRegistryTagCleared(git, gitlabProject.ID)
	log.Printf("pid:%d - Transfer project to a new name space %s with id %d\n", gitlabProjectId, gitlabDomainGroup.Name, gitlabDomainGroup.ID)

	_, res, err := git.Projects.TransferProject(gitlabProject.ID, &gitlab.TransferProjectOptions{
		Namespace: gitlabDomainGroup.ID,
	})
	if u.CheckErrNonFatal(err, "TransferProject TransferGroup") != nil {
		log.Fatalf("[ERROR] gitlab response is %s. pid:%d \n", u.JsonDump(res, "  "), gitlabProjectId)
	}
	if extraRegistryImageName != "" {
		ptn := regexp.MustCompile(`^[\/]+`)
		extraRegistryImageName = "/" + ptn.ReplaceAllString(extraRegistryImageName, "")
	}
	newRegistryImagePath := fmt.Sprintf(`%s%s`, GetContainerRegistryBaseLocation(git, gitlabProject.ID), extraRegistryImageName)
	for _, _repoImage := range repoImages {
		o := u.RunSystemCommand(fmt.Sprintf(`docker images %s --format "docker tag {{.Repository}}:{{.Tag}} %s:{{.Tag}} && docker push %s:{{.Tag}}"`, _repoImage, newRegistryImagePath, newRegistryImagePath), true)
		cmdList := strings.Split(o, "\n")
		batchChan := make(chan int, int(AppConfig["BatchSize"].(int64)) )
		defer close(batchChan)
		for idx, cmd := range(cmdList) {
			go func(_cmd string) {
				batchChan <- idx
				for _trycount := 0; _trycount < 5; _trycount++ {
					if o, err := u.RunSystemCommandV2(fmt.Sprintf(`bash -c "%s"`, _cmd), true); err != nil {
						log.Println(o)
						if _trycount == 4 {
							log.Printf("ERROR max try reached\n")
							<-batchChan
							return
						} else {
							log.Printf("ERRROR count %d - will retry\n", _trycount)
							time.Sleep(60*time.Second)
						}
					} else { break }
				}
				<-batchChan
			}(cmd)
		}
		log.Printf("Push %s completed\nStart to clean up ...\n", newRegistryImagePath)
		u.RunSystemCommand(fmt.Sprintf(
			`docker images %s --format "docker rmi {{.Repository}}:{{.Tag}}" | bash`,
			_repoImage), true)
		log.Printf("Cleanup %s completed\n", _repoImage)
	}
}