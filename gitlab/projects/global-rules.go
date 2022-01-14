package main

import (
	"log"
	u "localhost.com/utils"
	. "localhost.com/gitlab/model"
	"github.com/xanzy/go-gitlab"
)
// This bunch of functions applies some global rules to the system. Something like `Domain - All Team Reporter` belong to every projects with Reporter permission, for example.
// This is meant to be run daily to be sure our system has correct state.

func AllTeamShouldHaveReporterPermmisionOnAllProject(git *gitlab.Client) {
	AllTeamDomain := DomainNew("Domain - All Team Reporter")
	AllProjects := ProjectGet(map[string]string{"where": "namespace_kind = 'group'"})
	gitlabDomainAllTeam, _, err := git.Groups.GetGroup(AllTeamDomain.GitlabNamespaceId, nil)
	u.CheckErr(err, "AllTeamShouldHaveReporterPermmisionOnAllProject GetGroup")
	for _, project := range AllProjects {
		_, err := git.Projects.ShareProjectWithGroup(project.Pid, &gitlab.ShareWithGroupOptions{
			GroupID: &gitlabDomainAllTeam.ID,
			GroupAccess: gitlab.AccessLevel(GitlabPermissionLookup["ReporterPermissions"]),
		})
		u.CheckErrNonFatal(err, "AllTeamShouldHaveReporterPermmisionOnAllProject AccessLevel")
	}
}

func AllTeamShouldHaveDeveloperPermmisionOnTestCafe(git *gitlab.Client) {
	AllTeamDomain := DomainNew("Domain - All Team Reporter")
	AllProjects := ProjectGet(map[string]string{"where": "path_with_namespace = 'qa/cafe'"})
	u.Assert( len(AllProjects) == 1, "should return only one record", true)
	gitlabDomainAllTeam, _, err := git.Groups.GetGroup(AllTeamDomain.GitlabNamespaceId, nil)
	u.CheckErr(err, "AllTeamShouldHaveDeveloperPermmisionOnTestCafe GetGroup")
	for _, project := range AllProjects {
		success := false
		for ; ! success; {
		_, err := git.Projects.ShareProjectWithGroup(project.Pid, &gitlab.ShareWithGroupOptions{
			GroupID: &gitlabDomainAllTeam.ID,
			GroupAccess: gitlab.AccessLevel(GitlabPermissionLookup["DeveloperPermissions"]),
		})
		if u.CheckErrNonFatal(err, "AllTeamShouldHaveDeveloperPermmisionOnTestCafe AccessLevel") != nil {
		//If the group is already in it does not change the permission, it just return an error
		//u need to delete it first and share it again
			log.Printf("Gonna to delete the share \n")
			_, err := git.Projects.DeleteSharedProjectFromGroup(project.Pid, gitlabDomainAllTeam.ID, nil)
			u.CheckErr(err, "AllTeamShouldHaveDeveloperPermmisionOnTestCafe DeleteSharedProjectFromGroup")
		} else {
			success = true
		}
		}
	}
}

// This Domain - All Team Reporter is used to allow all people (devs) to do something so make sure it has all team member
func AllTeamShouldBeInTheDomainAllTeamReporter(git *gitlab.Client) {
	allTeams := TeamGet(map[string]string{"where": "1"})
	domainAllTeamReporter := DomainGet(map[string]string{"where": "name = 'Domain - All Team Reporter'"})[0]
	GitlabDomainAllTeamReporter, _, err := git.Groups.GetGroup(domainAllTeamReporter.GitlabNamespaceId, nil)
	u.CheckErr(err, "AllTeamShouldBeInTheDomainAllTeamReporter GetGroup")

	for _, team := range allTeams {
		TeamDomainNew(team.GitlabNamespaceId, domainAllTeamReporter.GitlabNamespaceId)
		_, _, err := git.Groups.ShareGroupWithGroup(GitlabDomainAllTeamReporter.ID, &gitlab.ShareGroupWithGroupOptions{
			GroupID: &team.GitlabNamespaceId,
			GroupAccess: gitlab.AccessLevel(GitlabPermissionLookup["OwnerPermissions"]),
		})
		u.CheckErrNonFatal(err, "AllTeamShouldBeInTheDomainAllTeamReporter ShareGroupWithGroup")
	}
}