package main

import (
	"log"
	"strings"
	u "localhost.com/utils"
	. "localhost.com/gitlab/model"
	"github.com/xanzy/go-gitlab"
)

//Scan the namespace table - for each name started with `Domain - ` - take that and get its members having `Team - `. Then update the table groupmember
// Goal is to know the Domain having the Team which is the new group we created for the project
func UpdateGroupMember(git *gitlab.Client) {
	nsWithDomainPrefix := GitlabNamespaceGet(map[string]string{"where": `name LIKE 'Domain - %'`})
	for _, ns := range nsWithDomainPrefix {
		aGroup, _, err := git.Groups.GetGroup(ns.GitlabNamespaceId, nil)
		if u.CheckNonErrIfMatch(err, "404 Group Not Found", "UpdateGroupMember GetGroup") != nil {
			log.Printf("[DEBUG] stale group ID %d - need to clean up\n", ns.GitlabNamespaceId)
			GitlabNamespaceDeleteOne(ns.GitlabNamespaceId)
			GroupmemberDeleteOne(ns.GitlabNamespaceId)
			continue
		}
		for _, sharedGroup := range aGroup.SharedWithGroups {
			if strings.HasPrefix(sharedGroup.GroupName, "Team - ") {
				log.Printf("[DEBUG] Found shared group member name started with 'Team - '")
				GroupmemberNew(aGroup.ID, sharedGroup.GroupID)
				domain := DomainNew(aGroup.Name)
				domain.HasTeam = 1
				domain.Update()
			}
		}
		adminUserId := int(AppConfig["admin_user_id"].(float64))
		accessLevel := GitlabPermissionLookup["MaintainerPermissions"]
		log.Printf("Allow user ID %d to be a maintainer of groupID %d required by the project transfer ops\n", adminUserId, aGroup.ID)
		_, _, err = git.GroupMembers.AddGroupMember(aGroup.ID, &gitlab.AddGroupMemberOptions{
			UserID: &adminUserId,
			AccessLevel: &accessLevel,
		}); u.CheckNonErrIfMatch(err, "Member already exists", "UpdateGroupMember AddGroupMember")
	}
}
