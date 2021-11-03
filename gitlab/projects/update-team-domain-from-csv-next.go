package main

import (
	"regexp"
	"strings"
	"fmt"
	"log"
	"encoding/csv"
	"os"
	u "localhost.com/utils"
	. "localhost.com/gitlab/model"
	"github.com/xanzy/go-gitlab"
	"github.com/xuri/excelize/v2"
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
			UpdateTeamDomainOneRow(git, idx, l)
		}
	}
}
func UpdateTeamOneRow(git *gitlab.Client, idx int, row []string) *Team {
	teamName := row[1]
	if teamName == "" {return nil}
	t := TeamNew(teamName)
	if t.GitlabNamespaceId == 0 { CreateGitlabTeam(git, &t) }
	return &t
}
func UpdateDomainOneRow(git *gitlab.Client, idx int, row []string) *Domain {
	domainName := row[1]
	if domainName == "" {return nil}
	d := DomainNew(domainName)
	if d.GitlabNamespaceId == 0 { CreateGitlabDomain(git, &d) }
	return &d
}
func UpdateTeamDomainFromExelNext(git *gitlab.Client, filename string) {
	f, err := excelize.OpenFile(filename)
	u.CheckErr(err, "UpdateTeamDomainFromExelNext OpenFile")
	lines, err := f.GetRows("Team"); u.CheckErr(err, "UpdateTeamDomainFromExelNext GetRows")
	for idx, l := range lines {
		if idx == 0 {continue}
		UpdateTeamOneRow(git, idx, l)
	}
	lines, err = f.GetRows("Domain"); u.CheckErr(err, "UpdateTeamDomainFromExelNext GetRows")
	for idx, l := range lines {
		if idx == 0 {continue}
		UpdateDomainOneRow(git, idx, l)
	}
	lines, err = f.GetRows("Team_Domain"); u.CheckErr(err, "UpdateTeamDomainFromExelNext GetRows")
	for idx, l := range lines {
		if idx == 0 {continue}
		UpdateTeamDomainOneRow(git, idx, l)
	}
}
func UpdateTeamDomainOneRow(git *gitlab.Client, idx int, l []string) *TeamDomain {
	//team_name,domain name, access level
	if l[0] == "" || l[1] == "" || l[2] == ""  { return nil }
	ts := TeamGet(map[string]string{"where":fmt.Sprintf("name = '%s'", l[0])})
	if ! u.Assert(len(ts) == 1, "Team should exists in Team table", false) { return nil }
	ds := DomainGet(map[string]string{"where":fmt.Sprintf("name = '%s'", l[1])})
	if ! u.Assert(len(ds) == 1, "Domain should exists in Domain table", false) {return nil}
	td := TeamDomainNew(ts[0].GitlabNamespaceId, ds[0].GitlabNamespaceId)
	td.Permission = l[2]
	td.Update()
	log.Printf("[DEBUG] %s\n", u.JsonDump(td, "  "))
	AddGitlabTeamToDomain(git, &ds[0])
	return &td
}
// One day I will make the two func into one only :)
func CreateGitlabDomain(git *gitlab.Client, d *Domain) {
	gName, gDesc := d.Name, "autocreated"
	gPath := MakeGitlabPathNameFromName(gName)
	log.Printf("[INFO] Going to create Domain as GitlabGroup - Path: '%s' - Name: '%s' - Description: '%s'\n", gPath, gName, gDesc)
	newGroup, _, err := git.Groups.CreateGroup(&gitlab.CreateGroupOptions{
		Name: &gName,
		Path: &gPath,
		Description: &gDesc,
	})
	u.CheckErr(err, "CreateGitlabDomain CreateGroup")
	d.GitlabNamespaceId = newGroup.ID ; d.Update()
}
func CreateGitlabTeam(git *gitlab.Client, d *Team) {
	gName, gDesc := d.Name, "autocreated"
	gPath := MakeGitlabPathNameFromName(gName)
	log.Printf("[INFO] Going to create Team as GitlabGroup - Path: '%s' - Name: '%s' - Description: '%s'\n", gPath, gName, gDesc)
	newGroup, _, err := git.Groups.CreateGroup(&gitlab.CreateGroupOptions{
		Name: &gName,
		Path: &gPath,
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
		u.CheckErrNonFatal(err, "AddGitlabTeamToDomain ShareGroupWithGroup")
	}
}

func MakeGitlabPathNameFromName(gName string) string {
	gName = strings.TrimSpace(gName)
	ptn := regexp.MustCompile(`[\s]+`)
	gPath := ptn.ReplaceAllString(strings.ToLower(gName), "-")
	ptn = regexp.MustCompile(`[\-]{2,}`)
	gPath = ptn.ReplaceAllString(gPath, "-")
	gPath = strings.TrimSpace(gPath)
	return gPath
}