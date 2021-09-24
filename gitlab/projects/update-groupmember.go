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
		aGroup, _, err := git.Groups.GetGroup(ns.GitlabNamespaceId, nil); u.CheckErr(err, "UpdateGroupMember")
		for _, sharedGroup := range aGroup.SharedWithGroups {
			if strings.HasPrefix(sharedGroup.GroupName, "Team - ") {
				log.Printf("[DEBUG] Found shafred group member name started with 'Team - '")
				GroupmemberNew(aGroup.ID, sharedGroup.GroupID)
			}
		}
	}
}
