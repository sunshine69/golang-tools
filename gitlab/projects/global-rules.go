package main

import (
	u "localhost.com/utils"
	. "localhost.com/gitlab/model"
	"github.com/xanzy/go-gitlab"
)
// This bunch of functions applies some global rules to the system. Something like `Domain - All Team Reporter` belong to every projects with Reporter permission, for example.
// This is meant to be run daily to be sure our system has correct state.

func AllTeamShouldHaveReporterPermmisiononOnAllProject(git *gitlab.Client) {
	AllTeamDomain := DomainNew("Domain - All Team Reporter")
	AllProjects := ProjectGet(map[string]string{"where": "namespace_kind = 'group'"})
	gitlabDomainAllTeam, _, err := git.Groups.GetGroup(AllTeamDomain.GitlabNamespaceId, nil)
	u.CheckErr(err, "AllTeamShouldHaveReporterPermmisiononOnAllProject GetGroup")
	for _, project := range AllProjects {
		u.CheckErr(err, "AllTeamShouldHaveReporterPermmisiononOnAllProject GetProject")
		_, err := git.Projects.ShareProjectWithGroup(project.Pid, &gitlab.ShareWithGroupOptions{
			GroupID: &gitlabDomainAllTeam.ID,
			GroupAccess: gitlab.AccessLevel(GitlabPermissionLookup["ReporterPermissions"]),
		})
		u.CheckErrNonFatal(err, "AllTeamShouldHaveReporterPermmisiononOnAllProject AccessLevel")
	}
}