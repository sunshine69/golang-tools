package main

import (
	"strings"
	"fmt"
	"log"
	"encoding/csv"
	"os"
	u "localhost.com/utils"
	_ "github.com/mattn/go-sqlite3"
	. "localhost.com/gitlab/model"
	"github.com/xanzy/go-gitlab"
)

var GitlabPermissionLookup map[string]gitlab.AccessLevelValue = map[string]gitlab.AccessLevelValue {
	"NoPermissions": 0,
	"MinimalAccessPermissions": 5,
	"GuestPermissions": 10,
	"ReporterPermissions": 20,
	"DeveloperPermissions": 30,
	"MaintainerPermissions": 40,
	"OwnerPermissions": 50,
}

//This script will update the team - domain but using our new sheet generated. The current one is set using sql select and parse from one small sheet (only have one row atm.) .Then we export the result for people to see and adjust/verify - See the sheet Team_Domain

//Now we export that into csv and update the team_domain table using that information using this script.

// As it is new and specific to fit for purpose we don't have to sanitize or hack around names etc. And that is why we put into separate file.

// Read a csv file input and parse it
func UpdateTeamDomainFromCSVNext(git *gitlab.Client, filename string) {
	csvFile, err := os.Open(filename); u.CheckErr(err, "UpdateTeamDomainFromCSVNext OpenCSV file")
	csvReader := csv.NewReader(csvFile)
	if lines, err := csvReader.ReadAll(); err == nil {
		for idx, l := range lines {
			if idx == 0 {continue}
			//team_name,domain name, access level
			if l[0] == "" || l[1] == "" || l[2] == ""  { continue }
			t := TeamNew(l[0])
			if t.GitlabNamespaceId == 0 { CreateGitlabTeam(git, &t) }
			d := DomainNew(l[1])
			if d.GitlabNamespaceId == 0 { CreateGitlabDomain(git, &d) }
			td := TeamDomainNew(t.GitlabNamespaceId, d.GitlabNamespaceId)
			td.Permission = l[2]
			td.Update()
			log.Printf("[DEBUG] %s\n", u.JsonDump(td, "  "))
			AddGitlabTeamToDomain(git, &d)
		}
	}
}
// One day I will make the two func into one only :)
func CreateGitlabDomain(git *gitlab.Client, d *Domain) {
	gName, gDesc := d.Name, "autocreated"
	gPath := strings.ReplaceAll(strings.ToLower(gName), " ", "")
	parentID := 0
	log.Printf("[INFO] Going to create Domain as GitlabGroup - Name: %s Description: %s\n", gName, gDesc)
	newGroup, _, err := git.Groups.CreateGroup(&gitlab.CreateGroupOptions{
		Name: &gName,
		Path: &gPath,
		ParentID: &parentID,
		Description: &gDesc,
	})
	u.CheckErr(err, "CreateGitlabDomain CreateGroup")
	d.GitlabNamespaceId = newGroup.ID ; d.Update()
}
func CreateGitlabTeam(git *gitlab.Client, d *Team) {
	gName, gDesc := d.Name, "autocreated"
	log.Printf("[INFO] Going to create Team as GitlabGroup - Name: %s Description: %s\n", gName, gDesc)
	gPath := strings.ReplaceAll(strings.ToLower(gName), " ", "")
	parentID := 0
	newGroup, _, err := git.Groups.CreateGroup(&gitlab.CreateGroupOptions{
		Name: &gName,
		Path: &gPath,
		ParentID: &parentID,
		Description: &gDesc,
	})
	u.CheckErr(err, "CreateGitlabTeam CreateGroup")
	d.GitlabNamespaceId = newGroup.ID ; d.Update()
}
func AddGitlabTeamToDomain(git *gitlab.Client, d *Domain) {
	tds := TeamDomainGet(map[string]string{"where": fmt.Sprintf("domain_id = %d", d.GitlabNamespaceId)})

	for _, teamd := range tds {
		_, _, err := git.Groups.ShareGroupWithGroup(d.GitlabNamespaceId, &gitlab.ShareGroupWithGroupOptions{
			GroupID: &(teamd.TeamId),
			GroupAccess: gitlab.AccessLevel(GitlabPermissionLookup[teamd.Permission]),
		})
		u.CheckErr(err, "AddGitlabTeamToDomain ShareGroupWithGroup")
	}
}
