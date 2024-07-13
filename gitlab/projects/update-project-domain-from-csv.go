package main

import (
	"log"
	"fmt"
	"strings"
	"encoding/csv"
	"os"
	u "localhost.com/utils"
	_ "github.com/mattn/go-sqlite3"
	. "localhost.com/gitlab/model"
)
//Make it sane again
func ProjectNameSanitize(pName string) string {
	o := strings.ReplaceAll(pName, "-prod", "")
	return o
}
//Give a name, get one project best match with pName and bunch of other rules, readon :)
func GetAProjectSmartly(pName string) Project {
	p := Project{}
	p.GetOne(map[string]string{
		"where": fmt.Sprintf("namespace_kind = 'group' and labels not like '%%,personal%%' and path_with_namespace like '%%%s%%'", pName),
	})
	return p
}
//Domain name mangling
var DomainNameLookupMap map[string]string = map[string]string {
	"Domain - Content Playback": "Domain - Content",
	"Domain - Learning Activities": "Domain - Learning Activity",
	"Domain - Provisioning Authentication": "Domain - Authentication",
	"Domain - Recommendations": "Domain - Recommendation",
	"Domain - Subscriptions": "Domain - Subscription",
	"Domain - User": "Domain - Users",
}
func FromCSVDomain2DomainName(s string) string {
	o := strings.Title(strings.ToLower(s))
	o = strings.ReplaceAll(o, "-", " ")
	o = "Domain - " + o
	o = strings.ReplaceAll(o, "  ", " ")
	if o1, ok := DomainNameLookupMap[o]; ok {
		return o1
	} else{
		return o
	}
}
//Give a name, get one project best match with pName and bunch of other rules, readon :)
func GetADomainSmartly(pName string) Domain {
	pName = FromCSVDomain2DomainName(pName)
	return DomainNew(pName)
}
// Read a csv file input and parse it
func UpdateProjectDomainFromCSV(filename string) {
	csvFile, err := os.Open(filename); u.CheckErr(err, "UpdateProjectDomainFromCSV OpenCSV file")
	csvReader := csv.NewReader(csvFile)
	if lines, err := csvReader.ReadAll(); err == nil {
		for idx, l := range lines {
			if idx == 0 {continue}
			//Service Name,Migration status,Type,QA,Domain,Ready for QA,Notes,Azure url,Running in Azure,Configuration Correct,E2E testing completed,Tech Lead Review,Old Team Name,Previous Feature Team
			if l[0] == "" || l[4] == "" || l[1] == "DO NOT MIGRATE"  { continue }
			p := GetAProjectSmartly( ProjectNameSanitize(l[0]) )
			if p.ID == 0 {continue}
			if  strings.TrimSpace(l[1]) == "DONE" {
				p.IsActive = 1; p.Update()
			}
			d := GetADomainSmartly(l[4])
			if d.GitlabNamespaceId == 0 {continue}
			pd := ProjectDomainNew(p.Pid, d.GitlabNamespaceId)
			log.Printf("[DEBUG] %s\n", u.JsonDump(pd, "  "))
		}
	}
}

func UpdateProjectDomainFromCSVSheet3(filename string) {
	csvFile, err := os.Open(filename); u.CheckErr(err, "UpdateProjectDomainFromCSVSheet3 OpenCSV file")
	csvReader := csv.NewReader(csvFile)
	if lines, err := csvReader.ReadAll(); err == nil {

		for idx, l := range lines {
			if idx == 0 || l[6] == "" {continue}
			//Repository,Domain,Status,Traffic (MB),Commit count,Note,Team
			// if l[0] == "" || l[4] == "" || l[2] == "won't move"  { continue }
			p := GetAProjectSmartly( ProjectNameSanitize(l[0]) )
			if p.Pid != 0 { //only update existing project
				if  l[3] == "0" && (l[4] == "" || l[4] == "0") {
					p.IsActive = 0; p.Update()
				}
			}
			//Project_Domain
			d := GetADomainSmartly(l[1])
			if p.ID != 0 && d.GitlabNamespaceId != 0 {
				pd := ProjectDomainNew(p.Pid, d.GitlabNamespaceId)
				log.Printf("[DEBUG] %s\n", u.JsonDump(pd, "  "))
			}
			//Project_Team
			t := TeamNew(l[6])
			if t.GitlabNamespaceId != 0 {//only deal with existing team
				if p.Pid != 0 {
					pt := TeamProjectNew(t.GitlabNamespaceId, p.Pid)
					log.Printf("[DEBUG] TeamProjectNew %s\n", u.JsonDump(pt, "  "))
				}
				//Team_Domain
				if d.GitlabNamespaceId != 0{
					td := TeamDomainNew(t.GitlabNamespaceId, d.GitlabNamespaceId)
					log.Printf("[DEBUG] TeamDomainNew %s\n", u.JsonDump(td, "  "))
				}
			} else {
				log.Printf("[DEBUG] Can not find team '%s'\n", l[6])
			}
		}

	}
}
