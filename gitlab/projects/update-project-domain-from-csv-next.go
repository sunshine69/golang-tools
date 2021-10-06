package main

import (
	"log"
	"encoding/csv"
	"os"
	u "localhost.com/utils"
	. "localhost.com/gitlab/model"
	"github.com/xuri/excelize/v2"
	"github.com/xanzy/go-gitlab"
)
//This script will update the project - domain but using our new sheet generated. Basically old one based on the sheet of previously AWS-Azure migration. Then we export the result for people to see and adjust/verify
//This final result will be exported to new csv and update using this script.

// As it is new and specific to fit for purpose we don't have to sanitize or hack around names etc. And that is why we put into separate file.

// Read a csv file input and parse it
//Depricated, we parsed exel file directly but keep here.
func UpdateProjectDomainFromCSVNext(git *gitlab.Client, filename string) {
	csvFile, err := os.Open(filename); u.CheckErr(err, "UpdateProjectDomainFromCSV OpenCSV file")
	csvReader := csv.NewReader(csvFile)
	if lines, err := csvReader.ReadAll(); err == nil {
		for idx, l := range lines {
			UpdateProjectDomainOneRow(git, idx, l)
		}
	}
}
func UpdateProjectDomainOneRow(git *gitlab.Client, idx int, l []string) {
	if idx == 0 || len(l) < 4 {return }
	//project name,path_with_namespace,weburl,domain name
    if l[3] != "" { log.Printf("DEBUG %s\n", u.JsonDump(l, "  ")) }
	if l[0] == "" || l[1] == "" || l[3] == ""  { return  }
	p := ProjectNew(l[1])
	if p.Pid == 0 {return }
	d := DomainNew(l[3])
	if d.GitlabNamespaceId == 0 {return }
	pd := ProjectDomainNew(p.Pid, d.GitlabNamespaceId)
	//Update project migration here so we don't have to run full update often
	UpdateProjectMigrationStatusOneRow(git, &p)
	log.Printf("[DEBUG] ProjectDomainNew %s\n", u.JsonDump(pd, "  "))
}
func UpdateProjectDomainFromExcelNext(git *gitlab.Client, filename string) {
	f, err := excelize.OpenFile(filename)
	u.CheckErr(err, "UpdateProjectDomainFromExcelNext OpenFile")
	rows, err := f.GetRows("Project_Domain")
	u.CheckErr(err, "UpdateProjectDomainFromExcelNext GetRows")
	for idx, l := range rows {
		UpdateProjectDomainOneRow(git, idx, l)
	}
}
