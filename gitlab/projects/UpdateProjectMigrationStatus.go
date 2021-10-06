package main

import (
	"fmt"
	"log"

	"github.com/xanzy/go-gitlab"
	. "localhost.com/gitlab/model"
	u "localhost.com/utils"
)
//Start from project, get the ROOT domain group of that project.
//Then check in the Groupdomain if exists
//If yes then Update the field domain_ownership_confirmed in project table
func UpdateProjectMigrationStatus(git *gitlab.Client) {
	dbc := GetDBConn()
	defer dbc.Close()
	projects := ProjectGet(map[string]string{"where":fmt.Sprintf("project.namespace_kind = 'group' AND project.labels NOT LIKE '%%personal%%' AND is_active = %d", 1)})
	for _, row := range projects {
		pRootDomain := row.GetDomainList(git)[0]
		domains := GroupmemberGet(map[string]string{"where": fmt.Sprintf("group_id = %d group by group_id", pRootDomain.ID)})
		if len(domains) > 0 {
			row.DomainOwnershipConfirmed = 1
		} else {
			row.DomainOwnershipConfirmed = 0
		}
		row.Update()
		log.Printf("[DEBUG] UpdateProjectMigrationStatus %s\n",u.JsonDump(row, "  "))
	}
	// Output and write csv file use sqlitebrowser better
}
