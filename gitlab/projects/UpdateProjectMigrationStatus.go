package main

import (
	"log"

	"github.com/xanzy/go-gitlab"
	. "localhost.com/gitlab/model"
	u "localhost.com/utils"
)

//Started from a GroupDomain as it is already a domain having team member. List all project associated then these projects has been migrated. Update the field domain_ownership_confirmed in project table
func UpdateProjectMigrationStatus(git *gitlab.Client) {
	dbc := GetDBConn()
	defer dbc.Close()
	domains := GroupmemberGet(map[string]string{"where": "1"})
	for _, row := range domains {
		ps, _, err := git.Groups.ListGroupProjects(row.GroupId, nil)
		u.CheckErr(err, "ReportProjectMigrationStatus ListGroupProjects")
		for _, p := range ps {
			aP := ProjectNew(p.PathWithNamespace)
			aP.DomainOwnershipConfirmed = 1
			aP.Update()
			log.Printf("[DEBUG] project %s\n", u.JsonDump(aP, "  "))
		}
	}
	// Output and write csv file use sqlitebrowser better
}
