package main

import (
	"log"
	"fmt"
	u "localhost.com/utils"
	. "localhost.com/gitlab/model"
	"github.com/xanzy/go-gitlab"
)
var GitlabAccesslevelLookup map[gitlab.AccessLevelValue]string = map[gitlab.AccessLevelValue]string {
	0: "NoPermissions",
	5: "MinimalAccessPermissions",
	10: "GuestPermissions",
	20: "ReporterPermissions",
	30: "DeveloperPermissions",
	40: "MaintainerPermissions",
	50: "OwnerPermissions",
}
func UpdateGitlabUser(git *gitlab.Client){
	userActive := true
	opt := gitlab.ListUsersOptions{
		ListOptions: gitlab.ListOptions{
			Page: 1,
			PerPage: 100,
		},
		Active: &userActive,
	}
	for {
		users, resp, err := git.Users.ListUsers(&opt)
		u.CheckErr(err, "UpdateGitlabUser ListUsers")
		for _, _u := range users {
			//We have not capture all data, only interested what we want, but can be added later on
			user := UserNew(_u.Email)
			user.GitlabUserId = _u.ID
			user.GitlabUserName = _u.Username
			user.Name = _u.Name
			user.Note = _u.Note
			user.Is_admin = (u.Ternary( _u.IsAdmin, 1, 0 )).(int)
			user.Organization = _u.Organization
			user.WebUrl = _u.WebURL
			user.Avatar_url = _u.AvatarURL
			user.Projects_limit = _u.ProjectsLimit
			user.Can_create_group = (u.Ternary(_u.CanCreateGroup, 1, 0)).(int)
			user.Can_create_project = (u.Ternary(_u.CanCreateProject, 1, 0)).(int)
			user.Using_license_seat = (u.Ternary(_u.UsingLicenseSeat, 1, 0)).(int)
			user.Two_factor_enabled = (u.Ternary(_u.TwoFactorEnabled, 1, 0)).(int)
			user.Shared_runners_minutes_limit = _u.SharedRunnersMinutesLimit
			user.Extra_shared_runners_minutes_limit = _u.ExtraSharedRunnersMinutesLimit
			user.External = (u.Ternary(_u.External, 1, 0)).(int)
			user.Update()
			getMemberShipType := "Namespace" // can be Project as well
			userMemberships, _, err := git.Users.GetUserMemberships(user.GitlabUserId, &gitlab.GetUserMembershipOptions{
				ListOptions: gitlab.ListOptions{
					Page: 1,
					PerPage: 100,
				},
				Type: &getMemberShipType,
			})
			if u.CheckErrNonFatal(err, "UpdateGitlabUser GetUserMemberships") != nil {
				log.Printf("ERROR user is: %s\n_u is: %s\n", u.JsonDump(user, "  "), u.JsonDump(_u, "  "))
			}
			for _, m := range userMemberships {
				teams := TeamGet(map[string]string{"where": fmt.Sprintf("gitlab_ns_id = %d", m.SourceID)})
				if len(teams) == 0 { continue }
				tu := TeamUserNew(m.SourceID, user.GitlabUserId)

				tu.Max_role = GitlabAccesslevelLookup[m.AccessLevel]
				tu.Update()
			}
		}
		if resp.CurrentPage >= resp.TotalPages {
			break
		}
		// Update the page number to get the next page.
		// opt.ListOptions.Page = resp.NextPage
		opt.Page = resp.NextPage
	}
}